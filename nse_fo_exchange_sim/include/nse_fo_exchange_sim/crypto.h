#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <openssl/aes.h>

namespace nse_fo_exchange_sim {

class Md5Digest {
public:
  static std::array<uint8_t, 16> compute(const uint8_t* data, std::size_t size);
};

class CtrCryptoStream {
public:
  CtrCryptoStream() = default;

  void initialize(const uint8_t* key, const uint8_t* iv);
  void xorData(uint8_t* data, std::size_t size);
  bool initialized() const { return initialized_; }

private:
  void refill();

  AES_KEY aes_key_ {};
  std::array<uint8_t, 16> counter_block_ {};
  std::array<uint8_t, 16> keystream_block_ {};
  std::size_t offset_ = keystream_block_.size();
  bool initialized_ = false;
};

}  // namespace nse_fo_exchange_sim
