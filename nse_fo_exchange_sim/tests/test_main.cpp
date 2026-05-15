#include "nse_fo_exchange_sim/config.h"
#include "nse_fo_exchange_sim/crypto.h"
#include "nse_fo_exchange_sim/protocol.h"
#include "nse_fo_exchange_sim/simulator.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <array>
#include <chrono>
#include <cstring>
#include <fstream>
#include <iostream>
#include <limits.h>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {

using namespace nse_fo_exchange_sim;
using namespace nse_fo_exchange_sim::protocol;

void require(bool condition, const std::string& message) {
  if (!condition) {
    throw std::runtime_error(message);
  }
}

uint64_t currentNanos() {
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
}

std::string trimRightSpaces(const uint8_t* data, std::size_t size) {
  std::string value(reinterpret_cast<const char*>(data), size);
  while (!value.empty() && (value.back() == ' ' || value.back() == '\0')) {
    value.pop_back();
  }
  return value;
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

int connectTcp(const std::string& host, uint16_t port) {
  const int fd = socket(AF_INET, SOCK_STREAM, 0);
  require(fd >= 0, "socket() failed");

  sockaddr_in addr {};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  require(inet_pton(AF_INET, host.c_str(), &addr.sin_addr) == 1, "inet_pton failed");
  require(connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0, "connect() failed");
  return fd;
}

int reserveUdpPort() {
  const int fd = socket(AF_INET, SOCK_DGRAM, 0);
  require(fd >= 0, "udp socket() failed");

  sockaddr_in addr {};
  addr.sin_family = AF_INET;
  addr.sin_port = 0;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  require(bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0, "udp bind() failed");

  sockaddr_in bound_addr {};
  socklen_t len = sizeof(bound_addr);
  require(getsockname(fd, reinterpret_cast<sockaddr*>(&bound_addr), &len) == 0, "udp getsockname failed");
  const int port = ntohs(bound_addr.sin_port);
  close(fd);
  return port;
}

void sendUdp(const std::string& host, uint16_t port, const void* payload, std::size_t size) {
  const int fd = socket(AF_INET, SOCK_DGRAM, 0);
  require(fd >= 0, "udp send socket() failed");

  sockaddr_in addr {};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  require(inet_pton(AF_INET, host.c_str(), &addr.sin_addr) == 1, "udp inet_pton failed");

  const ssize_t rc =
      sendto(fd, payload, size, 0, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
  close(fd);
  require(rc == static_cast<ssize_t>(size), "udp sendto failed");
}

std::string writeTokenFile(const std::string& build_root, const std::vector<uint32_t>& tokens) {
  const std::string path = build_root + "/test_tokens.txt";
  std::ofstream output(path);
  require(static_cast<bool>(output), "unable to create token file");
  for (uint32_t token : tokens) {
    output << token << '\n';
  }
  return path;
}

class SessionClient {
public:
  SessionClient(const std::string& host, uint16_t port)
      : fd_(connectTcp(host, port)) {}

  ~SessionClient() {
    if (fd_ >= 0) {
      close(fd_);
    }
  }

  void enableCrypto(const uint8_t* key, const uint8_t* iv) {
    outbound_crypto_.initialize(key, iv);
    inbound_crypto_.initialize(key, iv);
    encryption_enabled_ = true;
  }

  template <typename Payload>
  void sendPayload(const Payload& payload, bool corrupt_md5 = false) {
    std::vector<uint8_t> payload_bytes(reinterpret_cast<const uint8_t*>(&payload),
                                       reinterpret_cast<const uint8_t*>(&payload) + sizeof(payload));
    auto digest = Md5Digest::compute(payload_bytes.data(), payload_bytes.size());
    if (corrupt_md5) {
      digest[0] ^= 0xFF;
    }

    if (encryption_enabled_) {
      outbound_crypto_.xorData(payload_bytes.data(), payload_bytes.size());
    }

    DirectExCtclHeader header {};
    header.length = byteswap<uint16_t>(static_cast<uint16_t>(sizeof(header) + payload_bytes.size()));
    header.sequence_number = byteswap(++sequence_number_);
    std::memcpy(header.md5_checksum, digest.data(), digest.size());

    writeFully(fd_, &header, sizeof(header));
    writeFully(fd_, payload_bytes.data(), payload_bytes.size());
  }

  template <typename Payload>
  Payload receivePayload() {
    DirectExCtclHeader header {};
    readFully(fd_, &header, sizeof(header));
    const auto payload_size = byteswap(header.length) - sizeof(header);
    require(payload_size == sizeof(Payload), "unexpected payload size");

    std::vector<uint8_t> payload(payload_size);
    readFully(fd_, payload.data(), payload.size());
    if (encryption_enabled_) {
      inbound_crypto_.xorData(payload.data(), payload.size());
    }
    require(digestMatches(header.md5_checksum, payload), "payload MD5 mismatch");

    Payload decoded {};
    std::memcpy(&decoded, payload.data(), sizeof(decoded));
    return decoded;
  }

  template <typename Payload>
  std::optional<Payload> tryReceivePayload(int timeout_ms) {
    timeval timeout {};
    timeout.tv_sec = timeout_ms / 1000;
    timeout.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    DirectExCtclHeader header {};
    const ssize_t first_rc = recv(fd_, &header, sizeof(header), MSG_PEEK);
    if (first_rc < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      clearTimeout();
      return std::nullopt;
    }
    require(first_rc == static_cast<ssize_t>(sizeof(header)), "unexpected peek size");

    readFully(fd_, &header, sizeof(header));
    const auto payload_size = byteswap(header.length) - sizeof(header);
    require(payload_size == sizeof(Payload), "unexpected payload size");

    std::vector<uint8_t> payload(payload_size);
    readFully(fd_, payload.data(), payload.size());
    if (encryption_enabled_) {
      inbound_crypto_.xorData(payload.data(), payload.size());
    }
    require(digestMatches(header.md5_checksum, payload), "payload MD5 mismatch");

    Payload decoded {};
    std::memcpy(&decoded, payload.data(), sizeof(decoded));
    clearTimeout();
    return decoded;
  }

  bool waitForClose() {
    timeval timeout {};
    timeout.tv_sec = 1;
    setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    uint8_t byte = 0;
    const ssize_t rc = recv(fd_, &byte, sizeof(byte), 0);
    return rc <= 0;
  }

private:
  void clearTimeout() {
    timeval timeout {};
    setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  }

  bool digestMatches(const uint8_t* digest, const std::vector<uint8_t>& payload) {
    const auto expected = Md5Digest::compute(payload.data(), payload.size());
    return std::memcmp(digest, expected.data(), expected.size()) == 0;
  }

  int fd_ = -1;
  CtrCryptoStream outbound_crypto_;
  CtrCryptoStream inbound_crypto_;
  bool encryption_enabled_ = false;
  uint32_t sequence_number_ = 0;
};

GatewayRouterResponse runGatewayHandshake(uint16_t gateway_port, uint32_t user_id, uint16_t request_box_id) {
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();

  SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
  require(ctx != nullptr, "SSL_CTX_new failed");
  SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
  SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

  const int fd = connectTcp("127.0.0.1", gateway_port);
  SSL* ssl = SSL_new(ctx);
  require(ssl != nullptr, "SSL_new failed");
  SSL_set_fd(ssl, fd);
  require(SSL_connect(ssl) == 1, "SSL_connect failed");

  GatewayRouterRequest request {};
  request.ctcl_header.length = byteswap<uint16_t>(sizeof(request));
  request.ctcl_header.sequence_number = byteswap<uint32_t>(1);
  initializeMessageHeader(request.header, kTxnGatewayRouterRequest, user_id,
                          sizeof(request) - sizeof(request.ctcl_header));
  request.box_id = byteswap<uint16_t>(request_box_id);
  copyTrailingSpaces(request.broker_id, std::string("BRKR1"));
  const auto digest = Md5Digest::compute(
      reinterpret_cast<const uint8_t*>(&request.header),
      sizeof(request) - sizeof(request.ctcl_header));
  std::memcpy(request.ctcl_header.md5_checksum, digest.data(), digest.size());

  sslWriteFully(ssl, &request, sizeof(request));

  GatewayRouterResponse response {};
  sslReadFully(ssl, &response.ctcl_header, sizeof(response.ctcl_header));
  require(byteswap(response.ctcl_header.length) == sizeof(response), "bad gateway response length");
  sslReadFully(ssl, reinterpret_cast<uint8_t*>(&response) + sizeof(response.ctcl_header),
               sizeof(response) - sizeof(response.ctcl_header));

  SSL_shutdown(ssl);
  SSL_free(ssl);
  close(fd);
  SSL_CTX_free(ctx);
  return response;
}

void bootstrapReadySession(SessionClient& session,
                           const GatewayRouterResponse& gr_response,
                           uint32_t user_id,
                           uint16_t branch_id = 4) {
  SecureBoxRegistrationRequestPayload secure_box_req {};
  initializeMessageHeader(secure_box_req.header, kTxnSecureBoxRegistrationRequest, user_id,
                          sizeof(secure_box_req));
  secure_box_req.box_id = gr_response.box_id;
  session.sendPayload(secure_box_req);
  const auto secure_box_resp = session.receivePayload<SecureBoxRegistrationResponsePayload>();
  require(byteswap(secure_box_resp.header.transaction_code) == kTxnSecureBoxRegistrationResponse,
          "unexpected secure box response txn");

  session.enableCrypto(gr_response.cryptographic_key, gr_response.cryptographic_iv);

  BoxSignOnRequestPayload box_sign_on_req {};
  initializeMessageHeader(box_sign_on_req.header, kTxnBoxSignOnRequestIn, user_id,
                          sizeof(box_sign_on_req));
  box_sign_on_req.box_id = gr_response.box_id;
  copyTrailingSpaces(box_sign_on_req.broker_id, std::string("BRKR1"));
  box_sign_on_req.session_key = gr_response.session_key;
  session.sendPayload(box_sign_on_req);
  const auto box_sign_on_resp = session.receivePayload<BoxSignOnResponsePayload>();
  require(byteswap(box_sign_on_resp.header.transaction_code) == kTxnBoxSignOnRequestOut,
          "unexpected box sign on response txn");

  SignOnInPayload login_req {};
  initializeMessageHeader(login_req.header, kTxnLogonRequest, user_id, sizeof(login_req));
  login_req.user_id = byteswap(user_id);
  copyTrailingSpaces(login_req.password, std::string("PASS1234"));
  copyTrailingSpaces(login_req.new_password, std::string("PASS1234"));
  copyTrailingSpaces(login_req.broker_id, std::string("BRKR1"));
  login_req.branch_id = byteswap<uint16_t>(branch_id);
  login_req.version_number = byteswap<uint32_t>(1);
  copyTrailingSpaces(login_req.ws_class_name, std::string("1234567"));
  login_req.show_index = 'T';
  session.sendPayload(login_req);
  const auto login_resp = session.receivePayload<SignOnOutPayload>();
  require(byteswap(login_resp.header.transaction_code) == kTxnLogonResponse,
          "unexpected logon response txn");

  SystemInfoRequestPayload sys_info_req {};
  initializeMessageHeader(sys_info_req.header, kTxnSystemInfoRequest, user_id, sizeof(sys_info_req));
  session.sendPayload(sys_info_req);
  const auto sys_info_resp = session.receivePayload<SystemInfoResponsePayload>();
  require(byteswap(sys_info_resp.header.transaction_code) == kTxnSystemInfoResponse,
          "unexpected system info response txn");

  UpdateLocalDatabaseRequestPayload update_local_db_req {};
  initializeMessageHeader(update_local_db_req.header, kTxnUpdateLocalDatabase, user_id,
                          sizeof(update_local_db_req));
  update_local_db_req.request_for_open_orders = 'N';
  session.sendPayload(update_local_db_req);
  const auto update_local_db_resp = session.receivePayload<MessageHeader>();
  require(byteswap(update_local_db_resp.transaction_code) == kTxnUpdateLocalDatabaseTrailer,
          "unexpected update local db trailer txn");

  MessageHeader heartbeat {};
  initializeMessageHeader(heartbeat, kTxnHeartbeat, user_id, sizeof(heartbeat));
  session.sendPayload(heartbeat);

  MessageDownloadRequestPayload message_download_req {};
  initializeMessageHeader(message_download_req.header, kTxnMessageDownloadRequest, user_id,
                          sizeof(message_download_req));
  session.sendPayload(message_download_req);
  const auto message_download_resp = session.receivePayload<MessageHeader>();
  require(byteswap(message_download_resp.transaction_code) == kTxnMessageDownloadTrailer,
          "unexpected message download trailer txn");
}

void sendTbtOrder(const std::string& host,
                  uint16_t port,
                  uint8_t message_type,
                  uint32_t seq_no,
                  double order_id,
                  uint32_t token,
                  char side,
                  uint32_t price,
                  uint32_t quantity) {
  TbtOrderMessage message {};
  message.header.msg_len = sizeof(message);
  message.header.stream_id = 1;
  message.header.seq_no = seq_no;
  message.header.message_type = message_type;
  message.timestamp = currentNanos();
  message.order_id = order_id;
  message.token = token;
  message.order_type = static_cast<uint8_t>(side);
  message.price = price;
  message.quantity = quantity;
  sendUdp(host, port, &message, sizeof(message));
}

void sendTbtTrade(const std::string& host,
                  uint16_t port,
                  uint32_t seq_no,
                  double buy_order_id,
                  double sell_order_id,
                  uint32_t token,
                  uint32_t price,
                  uint32_t quantity) {
  TbtTradeMessage message {};
  message.header.msg_len = sizeof(message);
  message.header.stream_id = 1;
  message.header.seq_no = seq_no;
  message.header.message_type = 'T';
  message.timestamp = currentNanos();
  message.buy_order_id = buy_order_id;
  message.sell_order_id = sell_order_id;
  message.token = token;
  message.trade_price = price;
  message.trade_quantity = quantity;
  sendUdp(host, port, &message, sizeof(message));
}

OrderEntryRequestPayload makeFoOrderRequest(uint32_t user_id,
                                            uint32_t token,
                                            const std::string& symbol,
                                            uint16_t side,
                                            uint32_t quantity,
                                            uint32_t price,
                                            uint8_t order_flags1,
                                            uint32_t client_order_id,
                                            uint16_t unique_id) {
  OrderEntryRequestPayload request {};
  request.transaction_code = byteswap<uint16_t>(kTxnOrderEntryTrimmed);
  request.user_id = byteswap<uint32_t>(user_id);
  request.token_no = byteswap<uint32_t>(token);
  copyTrailingSpaces(request.contract_description.instrument_name, std::string("FUTIDX"));
  copyTrailingSpaces(request.contract_description.symbol, symbol);
  request.contract_description.expiry_date = byteswap<uint32_t>(20260528);
  request.book_type = byteswap<uint16_t>(1);
  request.buy_sell_indicator = byteswap<uint16_t>(side);
  request.disclosed_volume = byteswap<uint32_t>(quantity);
  request.volume = byteswap<uint32_t>(quantity);
  request.price = byteswap<uint32_t>(price);
  request.order_flags1 = order_flags1;
  request.branch_id = byteswap<uint16_t>(4);
  request.trader_id = byteswap<uint32_t>(user_id);
  copyTrailingSpaces(request.broker_id, std::string("BRKR1"));
  request.open_close = 'O';
  copyTrailingSpaces(request.settlor, std::string("SETTLOR0001"));
  request.pro_client_indicator = byteswap<uint16_t>(2);
  request.additional_flags = 0x2;
  request.filler = byteswap<uint32_t>(client_order_id);
  request.nnf_field = hostToWireDouble(123456.0);
  copyTrailingSpaces(request.pan, std::string("PAN1234567"));
  request.algo_id = byteswap<uint32_t>(77);
  request.unique_id = byteswap<uint16_t>(unique_id);
  return request;
}

void testCryptoRoundTrip() {
  std::array<uint8_t, 32> key {};
  std::array<uint8_t, 16> iv {};
  for (std::size_t i = 0; i < key.size(); ++i) {
    key[i] = static_cast<uint8_t>(i + 1);
  }
  for (std::size_t i = 0; i < iv.size(); ++i) {
    iv[i] = static_cast<uint8_t>(i + 3);
  }

  std::vector<uint8_t> data {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
  const auto original = data;

  CtrCryptoStream enc;
  CtrCryptoStream dec;
  enc.initialize(key.data(), iv.data());
  dec.initialize(key.data(), iv.data());

  enc.xorData(data.data(), data.size());
  dec.xorData(data.data(), data.size());
  require(data == original, "CTR round-trip failed");

  const auto digest1 = Md5Digest::compute(original.data(), original.size());
  const auto digest2 = Md5Digest::compute(original.data(), original.size());
  require(digest1 == digest2, "MD5 mismatch");
}

void testFullFlow() {
  Config config;
  config.listen_host = "127.0.0.1";
  config.gr_tls_port = 0;
  config.session_port = 0;
  config.box_id = 10;
  config.exchange_order_number_start = 123456;
  config.fill_number_start = 7;
  char cwd[PATH_MAX] {};
  require(getcwd(cwd, sizeof(cwd)) != nullptr, "getcwd failed");
  const std::string build_root = cwd;
  config.tls_cert_pem = build_root + "/testdata/tls/server.crt";
  config.tls_key_pem = build_root + "/testdata/tls/server.key";

  SimulatorApp app(config);
  app.start();
  std::this_thread::sleep_for(std::chrono::milliseconds(50));

  const uint32_t user_id = 991122;
  const auto gr_response = runGatewayHandshake(app.gatewayPort(), user_id, 99);
  require(byteswap(gr_response.header.transaction_code) == kTxnGatewayRouterResponse,
          "unexpected gateway response txn");
  require(byteswap(gr_response.box_id) == config.box_id, "unexpected gateway box id");
  require(trimRightSpaces(gr_response.ip, sizeof(gr_response.ip)) == "127.0.0.1",
          "unexpected gateway session host");
  require(byteswap(gr_response.port) == app.sessionPort(), "unexpected gateway session port");

  {
    SessionClient session("127.0.0.1", app.sessionPort());

    SecureBoxRegistrationRequestPayload secure_box_req {};
    initializeMessageHeader(secure_box_req.header, kTxnSecureBoxRegistrationRequest, user_id,
                            sizeof(secure_box_req));
    secure_box_req.box_id = gr_response.box_id;
    session.sendPayload(secure_box_req);
    const auto secure_box_resp = session.receivePayload<SecureBoxRegistrationResponsePayload>();
    require(byteswap(secure_box_resp.header.transaction_code) == kTxnSecureBoxRegistrationResponse,
            "unexpected secure box response txn");

    session.enableCrypto(gr_response.cryptographic_key, gr_response.cryptographic_iv);

    BoxSignOnRequestPayload box_sign_on_req {};
    initializeMessageHeader(box_sign_on_req.header, kTxnBoxSignOnRequestIn, user_id,
                            sizeof(box_sign_on_req));
    box_sign_on_req.box_id = gr_response.box_id;
    copyTrailingSpaces(box_sign_on_req.broker_id, std::string("BRKR1"));
    box_sign_on_req.session_key = gr_response.session_key;
    session.sendPayload(box_sign_on_req);
    const auto box_sign_on_resp = session.receivePayload<BoxSignOnResponsePayload>();
    require(byteswap(box_sign_on_resp.header.transaction_code) == kTxnBoxSignOnRequestOut,
            "unexpected box sign on response txn");

    SignOnInPayload login_req {};
    initializeMessageHeader(login_req.header, kTxnLogonRequest, user_id, sizeof(login_req));
    login_req.user_id = byteswap(user_id);
    copyTrailingSpaces(login_req.password, std::string("PASS1234"));
    copyTrailingSpaces(login_req.new_password, std::string("PASS1234"));
    copyTrailingSpaces(login_req.broker_id, std::string("BRKR1"));
    login_req.branch_id = byteswap<uint16_t>(4);
    login_req.version_number = byteswap<uint32_t>(1);
    copyTrailingSpaces(login_req.ws_class_name, std::string("1234567"));
    login_req.show_index = 'T';
    session.sendPayload(login_req);
    const auto login_resp = session.receivePayload<SignOnOutPayload>();
    require(byteswap(login_resp.header.transaction_code) == kTxnLogonResponse,
            "unexpected logon response txn");

    SystemInfoRequestPayload sys_info_req {};
    initializeMessageHeader(sys_info_req.header, kTxnSystemInfoRequest, user_id, sizeof(sys_info_req));
    session.sendPayload(sys_info_req);
    const auto sys_info_resp = session.receivePayload<SystemInfoResponsePayload>();
    require(byteswap(sys_info_resp.header.transaction_code) == kTxnSystemInfoResponse,
            "unexpected system info response txn");
    require(sys_info_resp.header.alpha_char[0] == config.default_stream_no,
            "unexpected stream count");

    UpdateLocalDatabaseRequestPayload update_local_db_req {};
    initializeMessageHeader(update_local_db_req.header, kTxnUpdateLocalDatabase, user_id,
                            sizeof(update_local_db_req));
    update_local_db_req.request_for_open_orders = 'N';
    session.sendPayload(update_local_db_req);
    const auto update_local_db_resp = session.receivePayload<MessageHeader>();
    require(byteswap(update_local_db_resp.transaction_code) == kTxnUpdateLocalDatabaseTrailer,
            "unexpected update local db trailer txn");

    MessageHeader heartbeat {};
    initializeMessageHeader(heartbeat, kTxnHeartbeat, user_id, sizeof(heartbeat));
    session.sendPayload(heartbeat);

    MessageDownloadRequestPayload message_download_req {};
    initializeMessageHeader(message_download_req.header, kTxnMessageDownloadRequest, user_id,
                            sizeof(message_download_req));
    session.sendPayload(message_download_req);
    const auto message_download_resp = session.receivePayload<MessageHeader>();
    require(byteswap(message_download_resp.transaction_code) == kTxnMessageDownloadTrailer,
            "unexpected message download trailer txn");

    OrderEntryRequestPayload unsupported_req {};
    unsupported_req.transaction_code = byteswap<uint16_t>(kTxnOrderEntryTrimmed);
    unsupported_req.user_id = byteswap<uint32_t>(user_id);
    unsupported_req.token_no = byteswap<uint32_t>(123456);
    copyTrailingSpaces(unsupported_req.contract_description.instrument_name, std::string("FUTIDX"));
    copyTrailingSpaces(unsupported_req.contract_description.symbol, std::string("BANKNIFTY"));
    unsupported_req.book_type = byteswap<uint16_t>(1);
    unsupported_req.buy_sell_indicator = byteswap<uint16_t>(1);
    unsupported_req.disclosed_volume = byteswap<uint32_t>(10);
    unsupported_req.volume = byteswap<uint32_t>(10);
    unsupported_req.price = byteswap<uint32_t>(42000);
    unsupported_req.order_flags1 = 0x4;
    unsupported_req.branch_id = byteswap<uint16_t>(4);
    unsupported_req.trader_id = byteswap<uint32_t>(user_id);
    copyTrailingSpaces(unsupported_req.broker_id, std::string("BRKR1"));
    unsupported_req.open_close = 'O';
    copyTrailingSpaces(unsupported_req.settlor, std::string("SETTLOR0001"));
    unsupported_req.pro_client_indicator = byteswap<uint16_t>(2);
    unsupported_req.additional_flags = 0x2;
    unsupported_req.filler = byteswap<uint32_t>(8001);
    unsupported_req.nnf_field = hostToWireDouble(111111.0);
    copyTrailingSpaces(unsupported_req.pan, std::string("PAN1234567"));
    unsupported_req.algo_id = byteswap<uint32_t>(77);
    unsupported_req.unique_id = byteswap<uint16_t>(9);
    session.sendPayload(unsupported_req);
    const auto unsupported_resp = session.receivePayload<OrderConfirmationPayload>();
    require(byteswap(unsupported_resp.transaction_code) == kTxnOrderErrorTrimmed,
            "unexpected unsupported order response txn");
    require(byteswap(unsupported_resp.error_code) == 1, "unexpected unsupported order error code");
    OrderEntryRequestPayload ioc_req {};
    ioc_req.transaction_code = byteswap<uint16_t>(kTxnOrderEntryTrimmed);
    ioc_req.user_id = byteswap<uint32_t>(user_id);
    ioc_req.token_no = byteswap<uint32_t>(123456);
    copyTrailingSpaces(ioc_req.contract_description.instrument_name, std::string("FUTIDX"));
    copyTrailingSpaces(ioc_req.contract_description.symbol, std::string("BANKNIFTY"));
    ioc_req.book_type = byteswap<uint16_t>(1);
    ioc_req.buy_sell_indicator = byteswap<uint16_t>(1);
    ioc_req.disclosed_volume = byteswap<uint32_t>(10);
    ioc_req.volume = byteswap<uint32_t>(10);
    ioc_req.price = byteswap<uint32_t>(42000);
    ioc_req.order_flags1 = 0x2;
    ioc_req.branch_id = byteswap<uint16_t>(4);
    ioc_req.trader_id = byteswap<uint32_t>(user_id);
    copyTrailingSpaces(ioc_req.broker_id, std::string("BRKR1"));
    ioc_req.open_close = 'O';
    copyTrailingSpaces(ioc_req.settlor, std::string("SETTLOR0001"));
    ioc_req.pro_client_indicator = byteswap<uint16_t>(2);
    ioc_req.additional_flags = 0x2;
    ioc_req.filler = byteswap<uint32_t>(8001);
    ioc_req.nnf_field = hostToWireDouble(111111.0);
    copyTrailingSpaces(ioc_req.pan, std::string("PAN1234567"));
    ioc_req.algo_id = byteswap<uint32_t>(77);
    ioc_req.unique_id = byteswap<uint16_t>(9);
    session.sendPayload(ioc_req);
    const auto ioc_ack = session.receivePayload<OrderConfirmationPayload>();
    require(byteswap(ioc_ack.transaction_code) == kTxnOrderConfirmationTrimmed,
            "unexpected IOC order confirmation txn");
    require(byteswap(ioc_ack.filler) == 8001, "unexpected IOC client order id echo");
    require(static_cast<uint64_t>(wireToHostDouble(ioc_ack.order_number)) ==
                config.exchange_order_number_start,
            "unexpected IOC exchange order number");

    const auto ioc_trade = session.receivePayload<TradeConfirmationPayload>();
    require(byteswap(ioc_trade.transaction_code) == kTxnTradeConfirmationTrimmed,
            "unexpected IOC trade confirmation txn");
    require(byteswap(ioc_trade.fill_quantity) == 10, "unexpected IOC trade qty");
    require(byteswap(ioc_trade.fill_price) == 42000, "unexpected IOC trade price");
    require(byteswap(ioc_trade.fill_number) == config.fill_number_start, "unexpected IOC fill number");

    OrderEntryRequestPayload order_req {};
    order_req.transaction_code = byteswap<uint16_t>(kTxnOrderEntryTrimmed);
    order_req.user_id = byteswap<uint32_t>(user_id);
    order_req.token_no = byteswap<uint32_t>(654321);
    copyTrailingSpaces(order_req.contract_description.instrument_name, std::string("FUTIDX"));
    copyTrailingSpaces(order_req.contract_description.symbol, std::string("NIFTY"));
    order_req.contract_description.expiry_date = byteswap<uint32_t>(20260528);
    order_req.book_type = byteswap<uint16_t>(1);
    order_req.buy_sell_indicator = byteswap<uint16_t>(1);
    order_req.disclosed_volume = byteswap<uint32_t>(25);
    order_req.volume = byteswap<uint32_t>(25);
    order_req.price = byteswap<uint32_t>(123450);
    order_req.order_flags1 = 0x2;
    order_req.branch_id = byteswap<uint16_t>(4);
    order_req.trader_id = byteswap<uint32_t>(user_id);
    copyTrailingSpaces(order_req.broker_id, std::string("BRKR1"));
    order_req.open_close = 'O';
    copyTrailingSpaces(order_req.settlor, std::string("SETTLOR0001"));
    order_req.pro_client_indicator = byteswap<uint16_t>(2);
    order_req.additional_flags = 0x2;
    order_req.filler = byteswap<uint32_t>(9001);
    order_req.nnf_field = hostToWireDouble(123456.0);
    copyTrailingSpaces(order_req.pan, std::string("PAN1234567"));
    order_req.algo_id = byteswap<uint32_t>(77);
    order_req.unique_id = byteswap<uint16_t>(11);
    session.sendPayload(order_req);

    const auto order_ack = session.receivePayload<OrderConfirmationPayload>();
    require(byteswap(order_ack.transaction_code) == kTxnOrderConfirmationTrimmed,
            "unexpected order confirmation txn");
    require(byteswap(order_ack.error_code) == 0, "unexpected order confirmation error");
    require(byteswap(order_ack.filler) == 9001, "unexpected client order id echo");
    require(static_cast<uint64_t>(wireToHostDouble(order_ack.order_number)) ==
                config.exchange_order_number_start + 1,
            "unexpected exchange order number");
    require(byteswap(order_ack.price) == 123450, "unexpected ack price");
    require(byteswap(order_ack.volume) == 25, "unexpected ack volume");

    const auto trade = session.receivePayload<TradeConfirmationPayload>();
    require(byteswap(trade.transaction_code) == kTxnTradeConfirmationTrimmed,
            "unexpected trade confirmation txn");
    require(byteswap(trade.fill_quantity) == 25, "unexpected trade qty");
    require(byteswap(trade.fill_price) == 123450, "unexpected trade price");
    require(byteswap(trade.fill_number) == config.fill_number_start + 1, "unexpected fill number");
    require(static_cast<uint64_t>(wireToHostDouble(trade.response_order_number)) ==
                config.exchange_order_number_start + 1,
            "unexpected trade exchange order number");

    OrderModifyCancelRequestPayload modify_req {};
    modify_req.transaction_code = byteswap<uint16_t>(kTxnOrderModificationRequestTrimmed);
    modify_req.user_id = byteswap<uint32_t>(user_id);
    modify_req.modified_cancelled_by = 'T';
    modify_req.token_no = order_req.token_no;
    std::memcpy(&modify_req.contract_description, &order_req.contract_description,
                sizeof(modify_req.contract_description));
    modify_req.order_number = order_ack.order_number;
    std::memcpy(modify_req.account_number, order_req.account_number, sizeof(modify_req.account_number));
    modify_req.book_type = order_req.book_type;
    modify_req.buy_sell_indicator = order_req.buy_sell_indicator;
    modify_req.disclosed_volume = 0;
    modify_req.disclosed_volume_remaining = 0;
    modify_req.total_volume_remaining = 0;
    modify_req.volume = 0;
    modify_req.volume_filled_today = order_req.volume;
    modify_req.price = byteswap<uint32_t>(123455);
    modify_req.good_till_date = order_req.good_till_date;
    modify_req.entry_date_time = order_ack.entry_date_time;
    modify_req.last_modified = order_ack.last_modified;
    modify_req.order_flags1 = order_req.order_flags1;
    modify_req.order_flags2 = order_req.order_flags2;
    modify_req.branch_id = order_req.branch_id;
    modify_req.trader_id = order_req.trader_id;
    std::memcpy(modify_req.broker_id, order_req.broker_id, sizeof(modify_req.broker_id));
    modify_req.open_close = order_req.open_close;
    std::memcpy(modify_req.settlor, order_req.settlor, sizeof(modify_req.settlor));
    modify_req.pro_client_indicator = order_req.pro_client_indicator;
    modify_req.additional_flags = order_req.additional_flags;
    modify_req.filler = order_req.filler;
    modify_req.nnf_field = order_req.nnf_field;
    std::memcpy(modify_req.pan, order_req.pan, sizeof(modify_req.pan));
    modify_req.algo_id = order_req.algo_id;
    modify_req.unique_id = order_req.unique_id;
    modify_req.last_activity_reference = order_ack.last_activity_reference;
    session.sendPayload(modify_req);
    const auto modify_resp = session.receivePayload<OrderConfirmationPayload>();
    require(byteswap(modify_resp.transaction_code) == kTxnOrderModificationErrorTrimmed,
            "unexpected modification error txn");
    require(byteswap(modify_resp.error_code) == kErrorOrderAlreadyFilled,
            "unexpected modification error code");
    require(byteswap(modify_resp.price) == 123450,
            "filled order price should remain unchanged after modification error");
    require(byteswap(modify_resp.volume_filled_today) == 25,
            "unexpected filled quantity after modification error");
    require(byteswap(modify_resp.total_volume_remaining) == 0,
            "filled order should not have remaining volume after modification error");
    require(byteswap(modify_resp.last_activity_reference) > byteswap(order_ack.last_activity_reference),
            "expected modification last activity reference to advance");

    PriceVolumeModificationRequestPayload price_vol_mod_req {};
    initializeMessageHeader(price_vol_mod_req.header, kTxnPriceVolModification, user_id,
                            sizeof(price_vol_mod_req));
    price_vol_mod_req.token_no = order_req.token_no;
    price_vol_mod_req.trader_id = byteswap<uint32_t>(user_id);
    price_vol_mod_req.order_number = order_ack.order_number;
    price_vol_mod_req.buy_sell = order_req.buy_sell_indicator;
    price_vol_mod_req.price = byteswap<uint32_t>(123460);
    price_vol_mod_req.volume = order_req.volume;
    price_vol_mod_req.last_modified = modify_resp.last_modified;
    price_vol_mod_req.filler = order_req.filler;
    price_vol_mod_req.last_activity_reference = modify_resp.last_activity_reference;
    session.sendPayload(price_vol_mod_req);
    const auto price_vol_mod_resp = session.receivePayload<OrderConfirmationPayload>();
    require(byteswap(price_vol_mod_resp.transaction_code) == kTxnOrderModificationErrorTrimmed,
            "unexpected price/volume modification error txn");
    require(byteswap(price_vol_mod_resp.error_code) == kErrorOrderAlreadyFilled,
            "unexpected price/volume modification error code");
    require(byteswap(price_vol_mod_resp.price) == 123450,
            "filled order price should remain unchanged after price/volume modification error");
    require(byteswap(price_vol_mod_resp.total_volume_remaining) == 0,
            "filled order should not have remaining volume after price/volume modification error");

    OrderModifyCancelRequestPayload cancel_req = modify_req;
    cancel_req.transaction_code = byteswap<uint16_t>(kTxnOrderCancellationRequestTrimmed);
    cancel_req.price = price_vol_mod_resp.price;
    cancel_req.last_activity_reference = price_vol_mod_resp.last_activity_reference;
    session.sendPayload(cancel_req);
    const auto cancel_resp = session.receivePayload<OrderConfirmationPayload>();
    require(byteswap(cancel_resp.transaction_code) == kTxnOrderCancellationConfirmationTrimmed,
            "unexpected cancellation confirmation txn");
    require(byteswap(cancel_resp.total_volume_remaining) == 0,
            "unexpected cancellation confirmation remaining volume");

    const auto bad_md5_gr = runGatewayHandshake(app.gatewayPort(), user_id + 1, 99);
    SessionClient bad_md5_session("127.0.0.1", app.sessionPort());
    secure_box_req.header.trader_id = byteswap<uint32_t>(user_id + 1);
    secure_box_req.box_id = bad_md5_gr.box_id;
    bad_md5_session.sendPayload(secure_box_req);
    static_cast<void>(bad_md5_session.receivePayload<SecureBoxRegistrationResponsePayload>());
    bad_md5_session.enableCrypto(bad_md5_gr.cryptographic_key, bad_md5_gr.cryptographic_iv);
    box_sign_on_req.header.trader_id = byteswap<uint32_t>(user_id + 1);
    box_sign_on_req.box_id = bad_md5_gr.box_id;
    box_sign_on_req.session_key = bad_md5_gr.session_key;
    bad_md5_session.sendPayload(box_sign_on_req);
    static_cast<void>(bad_md5_session.receivePayload<BoxSignOnResponsePayload>());
    login_req.header.trader_id = byteswap<uint32_t>(user_id + 1);
    login_req.user_id = byteswap<uint32_t>(user_id + 1);
    bad_md5_session.sendPayload(login_req);
    static_cast<void>(bad_md5_session.receivePayload<SignOnOutPayload>());
    bad_md5_session.sendPayload(order_req, true);
    require(bad_md5_session.waitForClose(), "session should close on bad MD5");
  }

  app.stop();
}

void testBookMatchingFlow() {
  Config config;
  config.listen_host = "127.0.0.1";
  config.gr_tls_port = 0;
  config.session_port = 0;
  config.box_id = 20;
  config.exchange_order_number_start = 200000;
  config.fill_number_start = 50;

  char cwd[PATH_MAX] {};
  require(getcwd(cwd, sizeof(cwd)) != nullptr, "getcwd failed");
  const std::string build_root = cwd;
  config.tls_cert_pem = build_root + "/testdata/tls/server.crt";
  config.tls_key_pem = build_root + "/testdata/tls/server.key";
  config.token_filter_file = writeTokenFile(build_root, {654321, 765432});
  config.max_book_contracts = 4;
  config.market_data_streams.push_back(MarketDataEndpoint {"127.0.0.1",
                                                           static_cast<uint16_t>(reserveUdpPort()),
                                                           "0.0.0.0"});

  SimulatorApp app(config);
  app.start();
  std::this_thread::sleep_for(std::chrono::milliseconds(50));

  const uint32_t user_id = 771122;
  const auto gr_response = runGatewayHandshake(app.gatewayPort(), user_id, 99);
  require(byteswap(gr_response.header.transaction_code) == kTxnGatewayRouterResponse,
          "unexpected gateway response txn");

  {
    SessionClient session("127.0.0.1", app.sessionPort());
    bootstrapReadySession(session, gr_response, user_id);

    auto first_order = makeFoOrderRequest(user_id, 654321, "NIFTY", 1, 25, 1000, 0x8, 9001, 11);
    session.sendPayload(first_order);
    const auto first_ack = session.receivePayload<OrderConfirmationPayload>();
    require(byteswap(first_ack.transaction_code) == kTxnOrderConfirmationTrimmed,
            "unexpected first order ack txn");
    require(!session.tryReceivePayload<TradeConfirmationPayload>(150).has_value(),
            "first order should not fill before market data");

    sendTbtOrder("127.0.0.1", config.market_data_streams.front().port, 'N', 1, 1001.0, 111111, 'S', 900, 10);
    require(!session.tryReceivePayload<TradeConfirmationPayload>(150).has_value(),
            "ignored token update should not fill the order");

    sendTbtOrder("127.0.0.1", config.market_data_streams.front().port, 'N', 2, 1002.0, 654321, 'S', 999, 10);
    const auto first_trade = session.receivePayload<TradeConfirmationPayload>();
    require(byteswap(first_trade.transaction_code) == kTxnTradeConfirmationTrimmed,
            "unexpected first market-data trade txn");
    require(byteswap(first_trade.fill_price) == 999, "unexpected first fill price");
    require(byteswap(first_trade.fill_quantity) == 10, "unexpected first fill quantity");
    require(byteswap(first_trade.remaining_volume) == 15, "unexpected first remaining quantity");
    require(byteswap(first_trade.disclosed_volume_remaining) == 15,
            "unexpected first disclosed remaining quantity");
    require(byteswap(first_trade.volume_filled_today) == 10, "unexpected first cumulative fill quantity");
    require(byteswap(first_trade.fill_number) == config.fill_number_start, "unexpected first fill number");
    require(!session.tryReceivePayload<TradeConfirmationPayload>(150).has_value(),
            "first order should still have a resting remainder");

    sendTbtOrder("127.0.0.1", config.market_data_streams.front().port, 'N', 3, 1003.0, 654321, 'S', 998, 7);
    const auto second_partial_trade = session.receivePayload<TradeConfirmationPayload>();
    require(byteswap(second_partial_trade.fill_price) == 998, "unexpected second partial fill price");
    require(byteswap(second_partial_trade.fill_quantity) == 7, "unexpected second partial fill quantity");
    require(byteswap(second_partial_trade.remaining_volume) == 8,
            "unexpected second partial remaining quantity");
    require(byteswap(second_partial_trade.disclosed_volume_remaining) == 8,
            "unexpected second partial disclosed remaining quantity");
    require(byteswap(second_partial_trade.volume_filled_today) == 17,
            "unexpected second partial cumulative fill quantity");
    require(byteswap(second_partial_trade.fill_number) == config.fill_number_start + 1,
            "unexpected second partial fill number");

    sendTbtOrder("127.0.0.1", config.market_data_streams.front().port, 'N', 4, 1004.0, 654321, 'S', 1000, 20);
    const auto final_first_trade = session.receivePayload<TradeConfirmationPayload>();
    require(byteswap(final_first_trade.fill_price) == 1000, "unexpected final first-order fill price");
    require(byteswap(final_first_trade.fill_quantity) == 8,
            "unexpected final first-order fill quantity");
    require(byteswap(final_first_trade.remaining_volume) == 0,
            "unexpected final first-order remaining quantity");
    require(byteswap(final_first_trade.volume_filled_today) == 25,
            "unexpected final first-order cumulative fill quantity");
    require(byteswap(final_first_trade.fill_number) == config.fill_number_start + 2,
            "unexpected final first-order fill number");

    auto second_order = makeFoOrderRequest(user_id, 654321, "NIFTY", 2, 15, 1200, 0x8, 9002, 12);
    session.sendPayload(second_order);
    const auto second_ack = session.receivePayload<OrderConfirmationPayload>();
    require(byteswap(second_ack.transaction_code) == kTxnOrderConfirmationTrimmed,
            "unexpected second order ack txn");
    require(!session.tryReceivePayload<TradeConfirmationPayload>(150).has_value(),
            "second order should rest before modification");

    sendTbtOrder("127.0.0.1", config.market_data_streams.front().port, 'N', 5, 2001.0, 654321, 'B', 995, 40);
    require(!session.tryReceivePayload<TradeConfirmationPayload>(150).has_value(),
            "second order should not fill on non-crossing bid");

    OrderUpdateRequestPayload modify_req {};
    modify_req.transaction_code = byteswap<uint16_t>(kTxnOrderModificationTrimmed);
    modify_req.user_id = byteswap<uint32_t>(user_id);
    modify_req.modified_cancelled_by = 'T';
    modify_req.token_no = byteswap<uint32_t>(654321);
    modify_req.contract_description = second_order.contract_description;
    modify_req.order_number = second_ack.order_number;
    modify_req.book_type = byteswap<uint16_t>(1);
    modify_req.buy_sell_indicator = byteswap<uint16_t>(2);
    modify_req.disclosed_volume = byteswap<uint32_t>(15);
    modify_req.disclosed_volume_remaining = byteswap<uint32_t>(15);
    modify_req.total_volume_remaining = byteswap<uint32_t>(15);
    modify_req.volume = byteswap<uint32_t>(15);
    modify_req.price = byteswap<uint32_t>(990);
    modify_req.entry_date_time = second_ack.entry_date_time;
    modify_req.last_modified = second_ack.last_modified;
    modify_req.order_flags1 = 0x8;
    modify_req.order_flags2 = 0x10;
    modify_req.branch_id = byteswap<uint16_t>(4);
    modify_req.trader_id = byteswap<uint32_t>(user_id);
    copyTrailingSpaces(modify_req.broker_id, std::string("BRKR1"));
    modify_req.open_close = 'O';
    copyTrailingSpaces(modify_req.settlor, std::string("SETTLOR0001"));
    modify_req.pro_client_indicator = byteswap<uint16_t>(2);
    modify_req.additional_flags = 0x2;
    modify_req.filler = byteswap<uint32_t>(9002);
    modify_req.nnf_field = hostToWireDouble(123456.0);
    copyTrailingSpaces(modify_req.pan, std::string("PAN1234567"));
    modify_req.algo_id = byteswap<uint32_t>(77);
    modify_req.unique_id = byteswap<uint16_t>(12);
    modify_req.last_activity_reference = second_ack.last_activity_reference;
    session.sendPayload(modify_req);

    const auto modify_ack = session.receivePayload<OrderConfirmationPayload>();
    require(byteswap(modify_ack.transaction_code) == kTxnOrderModificationConfirmationTrimmed,
            "unexpected modify confirmation txn");
    const auto modify_trade = session.receivePayload<TradeConfirmationPayload>();
    require(byteswap(modify_trade.transaction_code) == kTxnTradeConfirmationTrimmed,
            "unexpected modify trade txn");
    require(byteswap(modify_trade.fill_price) == 995, "unexpected modify fill price");
    require(byteswap(modify_trade.fill_quantity) == 15, "unexpected modify fill quantity");
    require(byteswap(modify_trade.fill_number) == config.fill_number_start + 3,
            "unexpected modify fill number");

    auto cancel_order = makeFoOrderRequest(user_id, 765432, "BANKNIFTY", 1, 5, 800, 0x8, 9003, 13);
    session.sendPayload(cancel_order);
    const auto cancel_ack = session.receivePayload<OrderConfirmationPayload>();
    require(byteswap(cancel_ack.transaction_code) == kTxnOrderConfirmationTrimmed,
            "unexpected cancel-target order ack txn");
    require(!session.tryReceivePayload<TradeConfirmationPayload>(150).has_value(),
            "cancel-target order should rest before cancellation");

    OrderUpdateRequestPayload cancel_req {};
    cancel_req.transaction_code = byteswap<uint16_t>(kTxnOrderCancellationTrimmed);
    cancel_req.user_id = byteswap<uint32_t>(user_id);
    cancel_req.modified_cancelled_by = 'T';
    cancel_req.token_no = byteswap<uint32_t>(765432);
    cancel_req.contract_description = cancel_order.contract_description;
    cancel_req.order_number = cancel_ack.order_number;
    cancel_req.book_type = byteswap<uint16_t>(1);
    cancel_req.buy_sell_indicator = byteswap<uint16_t>(1);
    cancel_req.disclosed_volume = byteswap<uint32_t>(5);
    cancel_req.disclosed_volume_remaining = byteswap<uint32_t>(5);
    cancel_req.total_volume_remaining = byteswap<uint32_t>(5);
    cancel_req.volume = byteswap<uint32_t>(5);
    cancel_req.price = byteswap<uint32_t>(800);
    cancel_req.entry_date_time = cancel_ack.entry_date_time;
    cancel_req.last_modified = cancel_ack.last_modified;
    cancel_req.order_flags1 = 0x8;
    cancel_req.branch_id = byteswap<uint16_t>(4);
    cancel_req.trader_id = byteswap<uint32_t>(user_id);
    copyTrailingSpaces(cancel_req.broker_id, std::string("BRKR1"));
    cancel_req.open_close = 'O';
    copyTrailingSpaces(cancel_req.settlor, std::string("SETTLOR0001"));
    cancel_req.pro_client_indicator = byteswap<uint16_t>(2);
    cancel_req.additional_flags = 0x2;
    cancel_req.filler = byteswap<uint32_t>(9003);
    cancel_req.nnf_field = hostToWireDouble(123456.0);
    copyTrailingSpaces(cancel_req.pan, std::string("PAN1234567"));
    cancel_req.algo_id = byteswap<uint32_t>(77);
    cancel_req.unique_id = byteswap<uint16_t>(13);
    cancel_req.last_activity_reference = cancel_ack.last_activity_reference;
    session.sendPayload(cancel_req);

    const auto cancel_conf = session.receivePayload<OrderConfirmationPayload>();
    require(byteswap(cancel_conf.transaction_code) == kTxnOrderCancellationConfirmationTrimmed,
            "unexpected cancellation confirmation txn");
    sendTbtOrder("127.0.0.1", config.market_data_streams.front().port, 'N', 6, 3001.0, 765432, 'S', 790, 20);
    require(!session.tryReceivePayload<TradeConfirmationPayload>(150).has_value(),
            "cancelled order should not fill");

    sendTbtOrder("127.0.0.1", config.market_data_streams.front().port, 'N', 7, 3002.0, 765432, 'S', 700, 5);
    auto ioc_hit = makeFoOrderRequest(user_id, 765432, "BANKNIFTY", 1, 12, 710, 0x2, 9004, 14);
    session.sendPayload(ioc_hit);
    const auto ioc_hit_ack = session.receivePayload<OrderConfirmationPayload>();
    require(byteswap(ioc_hit_ack.transaction_code) == kTxnOrderConfirmationTrimmed,
            "unexpected IOC hit ack txn");
    const auto ioc_hit_trade = session.receivePayload<TradeConfirmationPayload>();
    require(byteswap(ioc_hit_trade.fill_price) == 700, "unexpected IOC hit fill price");
    require(byteswap(ioc_hit_trade.fill_quantity) == 5, "unexpected IOC hit fill quantity");
    require(byteswap(ioc_hit_trade.remaining_volume) == 7, "unexpected IOC hit remaining quantity");
    require(byteswap(ioc_hit_trade.disclosed_volume_remaining) == 7,
            "unexpected IOC hit disclosed remaining quantity");
    require(byteswap(ioc_hit_trade.volume_filled_today) == 5,
            "unexpected IOC hit cumulative fill quantity");
    require(byteswap(ioc_hit_trade.fill_number) == config.fill_number_start + 4,
            "unexpected IOC hit fill number");
    const auto ioc_hit_cancel = session.receivePayload<OrderConfirmationPayload>();
    require(byteswap(ioc_hit_cancel.transaction_code) == kTxnOrderCancellationConfirmationTrimmed,
            "unexpected IOC hit cancellation txn");
    require(byteswap(ioc_hit_cancel.volume_filled_today) == 5,
            "unexpected IOC hit cancellation filled quantity");
    require(byteswap(ioc_hit_cancel.total_volume_remaining) == 0,
            "unexpected IOC hit cancellation remaining quantity");

    auto ioc_cancel = makeFoOrderRequest(user_id, 765432, "BANKNIFTY", 1, 7, 650, 0x2, 9005, 15);
    session.sendPayload(ioc_cancel);
    const auto ioc_cancel_ack = session.receivePayload<OrderConfirmationPayload>();
    require(byteswap(ioc_cancel_ack.transaction_code) == kTxnOrderConfirmationTrimmed,
            "unexpected IOC cancel ack txn");
    const auto ioc_cancel_resp = session.receivePayload<OrderConfirmationPayload>();
    require(byteswap(ioc_cancel_resp.transaction_code) == kTxnOrderCancellationConfirmationTrimmed,
            "unexpected IOC cancel txn");
    require(byteswap(ioc_cancel_resp.volume_filled_today) == 0,
            "unexpected IOC cancel filled quantity");
    require(byteswap(ioc_cancel_resp.total_volume_remaining) == 0,
            "unexpected IOC cancel remaining quantity");
  }

  app.stop();
}

}  // namespace

int main() {
  try {
    testCryptoRoundTrip();
    testFullFlow();
    testBookMatchingFlow();
    std::cout << "All simulator tests passed\n";
    return 0;
  } catch (const std::exception& ex) {
    std::cerr << "Test failure: " << ex.what() << '\n';
    return 1;
  }
}
