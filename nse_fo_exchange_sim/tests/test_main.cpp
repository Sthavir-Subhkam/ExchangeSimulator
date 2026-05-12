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
#include <iostream>
#include <limits.h>
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

  bool waitForClose() {
    timeval timeout {};
    timeout.tv_sec = 1;
    setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    uint8_t byte = 0;
    const ssize_t rc = recv(fd_, &byte, sizeof(byte), 0);
    return rc <= 0;
  }

private:
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
                config.exchange_order_number_start,
            "unexpected exchange order number");
    require(byteswap(order_ack.price) == 123450, "unexpected ack price");
    require(byteswap(order_ack.volume) == 25, "unexpected ack volume");

    const auto trade = session.receivePayload<TradeConfirmationPayload>();
    require(byteswap(trade.transaction_code) == kTxnTradeConfirmationTrimmed,
            "unexpected trade confirmation txn");
    require(byteswap(trade.fill_quantity) == 25, "unexpected trade qty");
    require(byteswap(trade.fill_price) == 123450, "unexpected trade price");
    require(byteswap(trade.fill_number) == config.fill_number_start, "unexpected fill number");
    require(static_cast<uint64_t>(wireToHostDouble(trade.response_order_number)) ==
                config.exchange_order_number_start,
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

}  // namespace

int main() {
  try {
    testCryptoRoundTrip();
    testFullFlow();
    std::cout << "All simulator tests passed\n";
    return 0;
  } catch (const std::exception& ex) {
    std::cerr << "Test failure: " << ex.what() << '\n';
    return 1;
  }
}
