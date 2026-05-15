#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <ctime>
#include <cstring>
#include <string>
#include <type_traits>

namespace nse_fo_exchange_sim {
namespace protocol {

constexpr uint16_t kTxnHeartbeat = 23506;
constexpr uint16_t kTxnGatewayRouterRequest = 2400;
constexpr uint16_t kTxnGatewayRouterResponse = 2401;
constexpr uint16_t kTxnBoxSignOnRequestIn = 23000;
constexpr uint16_t kTxnBoxSignOnRequestOut = 23001;
constexpr uint16_t kTxnSecureBoxRegistrationRequest = 23008;
constexpr uint16_t kTxnSecureBoxRegistrationResponse = 23009;
constexpr uint16_t kTxnLogonRequest = 2300;
constexpr uint16_t kTxnLogonResponse = 2301;
constexpr uint16_t kTxnSystemInfoRequest = 1600;
constexpr uint16_t kTxnSystemInfoResponse = 1601;
constexpr uint16_t kTxnUpdateLocalDatabase = 7300;
constexpr uint16_t kTxnUpdateLocalDatabaseTrailer = 7308;
constexpr uint16_t kTxnMessageDownloadRequest = 7000;
constexpr uint16_t kTxnMessageDownloadTrailer = 7031;
constexpr uint16_t kTxnPriceVolModification = 2013;
constexpr uint16_t kTxnOrderEntryTrimmed = 20000;
constexpr uint16_t kTxnOrderConfirmationTrimmed = 20073;
constexpr uint16_t kTxnOrderErrorTrimmed = 20231;
constexpr uint16_t kTxnOrderModificationRequestTrimmed = 20040;
constexpr uint16_t kTxnOrderModificationConfirmationTrimmed = 20074;
constexpr uint16_t kTxnOrderModificationErrorTrimmed = 20042;
constexpr uint16_t kTxnOrderCancellationRequestTrimmed = 20070;
constexpr uint16_t kTxnOrderModificationTrimmed = 20040;
constexpr uint16_t kTxnOrderModificationConfirmationTrimmed = 20074;
constexpr uint16_t kTxnOrderModificationErrorTrimmed = 20042;
constexpr uint16_t kTxnOrderCancellationTrimmed = 20070;
constexpr uint16_t kTxnOrderCancellationConfirmationTrimmed = 20075;
constexpr uint16_t kTxnOrderCancellationErrorTrimmed = 20072;
constexpr uint16_t kTxnTradeConfirmationTrimmed = 20222;

constexpr uint16_t kErrorUnsupportedOrder = 1;
constexpr uint16_t kErrorUnknownOrder = 2;
constexpr uint16_t kErrorOrderAlreadyFilled = 3;
constexpr uint8_t kOrderFlagsIoc = 0x2;
constexpr uint8_t kOrderFlagsDay = 0x8;

template <typename T>
inline T byteswap(T value) {
  static_assert(std::is_integral<T>::value, "byteswap expects integral types");
  if constexpr (sizeof(T) == sizeof(uint16_t)) {
    return static_cast<T>(__builtin_bswap16(static_cast<uint16_t>(value)));
  }
  if constexpr (sizeof(T) == sizeof(uint32_t)) {
    return static_cast<T>(__builtin_bswap32(static_cast<uint32_t>(value)));
  }
  if constexpr (sizeof(T) == sizeof(uint64_t)) {
    return static_cast<T>(__builtin_bswap64(static_cast<uint64_t>(value)));
  }
  return value;
}

inline double hostToWireDouble(double value) {
  uint64_t bits = 0;
  std::memcpy(&bits, &value, sizeof(bits));
  bits = byteswap(bits);
  double wire_value = 0;
  std::memcpy(&wire_value, &bits, sizeof(wire_value));
  return wire_value;
}

inline double wireToHostDouble(double value) {
  uint64_t bits = 0;
  std::memcpy(&bits, &value, sizeof(bits));
  bits = byteswap(bits);
  double host_value = 0;
  std::memcpy(&host_value, &bits, sizeof(host_value));
  return host_value;
}

template <typename T>
inline void zeroObject(T& value) {
  std::memset(&value, 0, sizeof(T));
}

template <typename Array>
inline void copyTrailingSpaces(Array& dst, const std::string& value) {
  std::fill(std::begin(dst), std::end(dst), static_cast<uint8_t>(' '));
  const std::size_t copy_size = std::min(value.size(), sizeof(dst));
  std::memcpy(dst, value.data(), copy_size);
}

template <typename Array>
inline void copyCString(Array& dst, const std::string& value) {
  std::fill(std::begin(dst), std::end(dst), static_cast<uint8_t>(0));
  const std::size_t copy_size = sizeof(dst) == 0 ? 0 : std::min(value.size(), sizeof(dst) - 1);
  std::memcpy(dst, value.data(), copy_size);
}

#pragma pack(push, 2)

struct DirectExCtclHeader {
  uint16_t length;
  uint32_t sequence_number;
  uint8_t md5_checksum[16];
};

struct MessageHeader {
  uint16_t transaction_code;
  uint32_t log_time;
  uint8_t alpha_char[2];
  uint32_t trader_id;
  uint16_t error_code;
  uint64_t time_stamp;
  uint64_t time_stamp1;
  uint8_t time_stamp2[8];
  uint16_t message_length;
};

struct GatewayRouterRequest {
  DirectExCtclHeader ctcl_header;
  MessageHeader header;
  uint16_t box_id;
  uint8_t broker_id[5];
  uint8_t reserved;
};

struct GatewayRouterResponse {
  DirectExCtclHeader ctcl_header;
  MessageHeader header;
  uint16_t box_id;
  uint8_t broker_id[5];
  uint8_t reserved;
  uint8_t ip[16];
  uint32_t port;
  uint64_t session_key;
  uint8_t cryptographic_key[32];
  uint8_t cryptographic_iv[16];
};

struct SecureBoxRegistrationRequestPayload {
  MessageHeader header;
  uint16_t box_id;
};

struct SecureBoxRegistrationResponsePayload {
  MessageHeader header;
};

struct BoxSignOnRequestPayload {
  MessageHeader header;
  uint16_t box_id;
  uint8_t broker_id[5];
  uint8_t reserved[5];
  uint64_t session_key;
};

struct BoxSignOnResponsePayload {
  MessageHeader header;
  uint16_t box_id;
  uint8_t reserved[10];
};

struct SignOnInPayload {
  MessageHeader header;
  uint32_t user_id;
  uint8_t reserved1[8];
  uint8_t password[8];
  uint8_t reserved2[8];
  uint8_t new_password[8];
  uint8_t trader_name[26];
  uint32_t last_password_change_date;
  uint8_t broker_id[5];
  uint8_t reserved3;
  uint16_t branch_id;
  uint32_t version_number;
  uint32_t batch_2_start_time;
  uint8_t host_switch_context;
  uint8_t colour[50];
  uint8_t reserved4;
  uint16_t user_type;
  double sequence_number;
  uint8_t ws_class_name[14];
  uint8_t broker_status;
  uint8_t show_index;
  uint16_t st_broker_eligibility_per_mkt;
  uint16_t member_type;
  uint8_t clearing_status;
  uint8_t broker_name[25];
  uint8_t reserved5[16];
  uint8_t reserved6[16];
  uint8_t reserved7[16];
};

struct SignOnOutPayload {
  MessageHeader header;
  uint32_t user_id;
  uint8_t reserved1[8];
  uint8_t password[8];
  uint8_t reserved2[8];
  uint8_t new_password[8];
  uint8_t trader_name[26];
  uint32_t last_password_change_date;
  uint8_t broker_id[5];
  uint8_t reserved3;
  uint16_t branch_id;
  uint32_t version_number;
  uint32_t end_time;
  uint8_t reserved4;
  uint8_t colour[50];
  uint8_t reserved5;
  uint16_t user_type;
  double sequence_number;
  uint8_t ws_class_name[14];
  uint8_t broker_status;
  uint8_t show_index;
  uint16_t st_broker_eligibility_per_mkt;
  uint16_t member_type;
  uint8_t clearing_status;
  uint8_t broker_name[25];
  uint8_t reserved6[16];
  uint8_t reserved7[16];
  uint8_t reserved8[16];
};

struct SystemInfoRequestPayload {
  MessageHeader header;
  uint32_t last_update_portfolio_time;
};

struct MarketStatus {
  uint16_t normal;
  uint16_t odd_lot;
  uint16_t spot;
  uint16_t auction;
};

struct SystemInfoResponsePayload {
  MessageHeader header;
  MarketStatus st_market_status;
  MarketStatus st_ex_market_status;
  MarketStatus st_pl_market_status;
  uint8_t update_portfolio;
  uint32_t market_index;
  uint16_t default_settlement_period_normal;
  uint16_t default_settlement_period_spot;
  uint16_t default_settlement_period_auction;
  uint16_t competitor_period;
  uint16_t solicitor_period;
  uint16_t warning_percent;
  uint16_t volume_freeze_percent;
  uint16_t snap_quote_time;
  uint16_t reserved;
  uint32_t board_lot_quantity;
  uint32_t tick_size;
  uint16_t maximum_gtc_days;
  uint8_t st_stock_eligible_indicators;
  uint16_t disclosed_quantity_percent_allowed;
  uint32_t risk_free_interest_rate;
};

struct UpdateLocalDatabaseRequestPayload {
  MessageHeader header;
  uint32_t last_update_security_time;
  uint32_t last_update_participant_time;
  uint32_t last_update_instrument_time;
  uint32_t last_update_index_time;
  uint8_t request_for_open_orders;
  uint8_t reserved;
  MarketStatus st_ms;
  MarketStatus st_ex_ms;
  MarketStatus st_pl_ms;
};

struct MessageDownloadRequestPayload {
  MessageHeader header;
  uint64_t sequence_number;
};

struct ContractDescTr {
  uint8_t instrument_name[6];
  uint8_t symbol[10];
  uint32_t expiry_date;
  uint32_t strike_price;
  uint8_t option_type[2];
};

struct OrderEntryRequestPayload {
  uint16_t transaction_code;
  uint32_t user_id;
  uint16_t reason_code;
  uint32_t token_no;
  ContractDescTr contract_description;
  uint8_t account_number[10];
  uint16_t book_type;
  uint16_t buy_sell_indicator;
  uint32_t disclosed_volume;
  uint32_t volume;
  uint32_t price;
  uint32_t good_till_date;
  uint8_t order_flags1;
  uint8_t order_flags2;
  uint16_t branch_id;
  uint32_t trader_id;
  uint8_t broker_id[5];
  uint8_t open_close;
  uint8_t settlor[12];
  uint16_t pro_client_indicator;
  uint8_t additional_flags;
  uint32_t filler;
  double nnf_field;
  uint8_t pan[10];
  uint32_t algo_id;
  uint16_t unique_id;
  uint8_t reserved4[32];
};

struct OrderUpdateRequestPayload {
  uint16_t transaction_code;
  uint32_t user_id;
  uint8_t modified_cancelled_by;
  uint8_t reserved;
  uint32_t token_no;
  ContractDescTr contract_description;
  double order_number;
  uint8_t account_number[10];
  uint16_t book_type;
  uint16_t buy_sell_indicator;
  uint32_t disclosed_volume;
  uint32_t disclosed_volume_remaining;
  uint32_t total_volume_remaining;
  uint32_t volume;
  uint32_t volume_filled_today;
  uint32_t price;
  uint32_t good_till_date;
  uint32_t entry_date_time;
  uint32_t last_modified;
  uint8_t order_flags1;
  uint8_t order_flags2;
  uint16_t branch_id;
  uint32_t trader_id;
  uint8_t broker_id[5];
  uint8_t open_close;
  uint8_t settlor[12];
  uint16_t pro_client_indicator;
  uint8_t additional_flags;
  uint32_t filler;
  double nnf_field;
  uint8_t pan[10];
  uint32_t algo_id;
  uint16_t unique_id;
  uint64_t last_activity_reference;
  uint8_t reserved4[24];
};

struct OrderConfirmationPayload {
  uint16_t transaction_code;
  uint32_t log_time;
  uint32_t user_id;
  uint16_t error_code;
  uint64_t time_stamp1;
  uint8_t time_stamp2;
  uint8_t modified_cancelled_by;
  uint16_t reason_code;
  uint32_t token_no;
  ContractDescTr contract_description;
  uint8_t close_out_flag;
  double order_number;
  uint8_t account_number[10];
  uint16_t book_type;
  uint16_t buy_sell_indicator;
  uint32_t disclosed_volume;
  uint32_t disclosed_volume_remaining;
  uint32_t total_volume_remaining;
  uint32_t volume;
  uint32_t volume_filled_today;
  uint32_t price;
  uint32_t good_till_date;
  uint32_t entry_date_time;
  uint32_t last_modified;
  uint8_t order_flags1;
  uint8_t order_flags2;
  uint16_t branch_id;
  uint32_t trader_id;
  uint8_t broker_id[5];
  uint8_t open_close;
  uint8_t settlor[12];
  uint16_t pro_client_indicator;
  uint8_t additional_flags;
  uint32_t filler;
  double nnf_field;
  uint64_t time_stamp3;
  uint8_t pan[10];
  uint32_t algo_id;
  uint16_t unique_id;
  uint64_t last_activity_reference;
  uint8_t reserved4[52];
};

struct OrderModifyCancelRequestPayload {
  uint16_t transaction_code;
  uint32_t user_id;
  uint8_t modified_cancelled_by;
  uint8_t reserved;
  uint32_t token_no;
  ContractDescTr contract_description;
  double order_number;
  uint8_t account_number[10];
  uint16_t book_type;
  uint16_t buy_sell_indicator;
  uint32_t disclosed_volume;
  uint32_t disclosed_volume_remaining;
  uint32_t total_volume_remaining;
  uint32_t volume;
  uint32_t volume_filled_today;
  uint32_t price;
  uint32_t good_till_date;
  uint32_t entry_date_time;
  uint32_t last_modified;
  uint8_t order_flags1;
  uint8_t order_flags2;
  uint16_t branch_id;
  uint32_t trader_id;
  uint8_t broker_id[5];
  uint8_t open_close;
  uint8_t settlor[12];
  uint16_t pro_client_indicator;
  uint8_t additional_flags;
  uint32_t filler;
  double nnf_field;
  uint8_t pan[10];
  uint32_t algo_id;
  uint16_t unique_id;
  uint64_t last_activity_reference;
  uint8_t reserved4[24];
};

struct PriceVolumeModificationRequestPayload {
  MessageHeader header;
  uint32_t token_no;
  uint32_t trader_id;
  double order_number;
  uint16_t buy_sell;
  uint32_t price;
  uint32_t volume;
  uint32_t last_modified;
  uint32_t filler;
  uint64_t last_activity_reference;
  uint8_t reserved[24];
};

struct TradeConfirmationPayload {
  uint16_t transaction_code;
  uint32_t log_time;
  uint32_t trader_id;
  uint64_t time_stamp;
  uint64_t time_stamp1;
  uint8_t time_stamp2[8];
  double response_order_number;
  uint8_t broker_id[5];
  uint8_t reserved;
  uint8_t account_number[10];
  uint16_t buy_sell_indicator;
  uint32_t original_volume;
  uint32_t disclosed_volume;
  uint32_t remaining_volume;
  uint32_t disclosed_volume_remaining;
  uint32_t price;
  uint8_t order_flags1;
  uint8_t order_flags2;
  uint32_t good_till_date;
  uint32_t fill_number;
  uint32_t fill_quantity;
  uint32_t fill_price;
  uint32_t volume_filled_today;
  uint8_t activity_type[2];
  uint32_t activity_time;
  uint32_t token;
  ContractDescTr contract_description;
  uint8_t open_close;
  uint8_t book_type;
  uint8_t participant[12];
  uint8_t additional_flags;
  uint8_t pan[10];
  uint32_t algo_id;
  uint16_t reserved3;
  uint64_t last_activity_reference;
  uint8_t reserved4[52];
};

#pragma pack(pop)

#pragma pack(push, 1)

struct TbtStreamHeader {
  uint16_t msg_len;
  uint16_t stream_id;
  uint32_t seq_no;
  uint8_t message_type;
};

struct TbtOrderMessage {
  TbtStreamHeader header;
  uint64_t timestamp;
  double order_id;
  uint32_t token;
  uint8_t order_type;
  uint32_t price;
  uint32_t quantity;
};

struct TbtTradeMessage {
  TbtStreamHeader header;
  uint64_t timestamp;
  double buy_order_id;
  double sell_order_id;
  uint32_t token;
  uint32_t trade_price;
  uint32_t trade_quantity;
};

#pragma pack(pop)

static_assert(sizeof(DirectExCtclHeader) == 22, "Unexpected CTCL header size");

inline void initializeMessageHeader(MessageHeader& header,
                                    uint16_t transaction_code,
                                    uint32_t trader_id,
                                    uint16_t payload_size) {
  zeroObject(header);
  header.transaction_code = byteswap(transaction_code);
  header.log_time = byteswap(static_cast<uint32_t>(time(nullptr)));
  header.alpha_char[0] = ' ';
  header.alpha_char[1] = ' ';
  header.trader_id = byteswap(trader_id);
  header.message_length = byteswap(payload_size);
}

}  // namespace protocol
}  // namespace nse_fo_exchange_sim
