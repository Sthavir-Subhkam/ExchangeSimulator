#include "nse_fo_exchange_sim/crypto.h"

#include <openssl/evp.h>

#include <array>
#include <cstring>
#include <stdexcept>

namespace nse_fo_exchange_sim {

std::array<uint8_t, 16> Md5Digest::compute(const uint8_t* data, std::size_t size) {
  std::array<uint8_t, 16> digest {};
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (ctx == nullptr) {
    throw std::runtime_error("EVP_MD_CTX_new failed");
  }

  unsigned int digest_size = 0;
  if (EVP_DigestInit_ex(ctx, EVP_md5(), nullptr) != 1 ||
      EVP_DigestUpdate(ctx, data, size) != 1 ||
      EVP_DigestFinal_ex(ctx, digest.data(), &digest_size) != 1) {
    EVP_MD_CTX_free(ctx);
    throw std::runtime_error("MD5 digest computation failed");
  }

  EVP_MD_CTX_free(ctx);
  if (digest_size != digest.size()) {
    throw std::runtime_error("Unexpected MD5 digest size");
  }
  return digest;
}

void CtrCryptoStream::initialize(const uint8_t* key, const uint8_t* iv) {
  if (AES_set_encrypt_key(key, 256, &aes_key_) != 0) {
    throw std::runtime_error("AES_set_encrypt_key failed");
  }

  std::memset(counter_block_.data(), 0, counter_block_.size());
  std::memcpy(counter_block_.data(), iv, 12);
  counter_block_[12] = 0;
  counter_block_[13] = 0;
  counter_block_[14] = 0;
  counter_block_[15] = 2;
  offset_ = keystream_block_.size();
  initialized_ = true;
}

void CtrCryptoStream::refill() {
  AES_encrypt(counter_block_.data(), keystream_block_.data(), &aes_key_);

  uint32_t ctr = static_cast<uint32_t>(counter_block_[12]) << 24 |
                 static_cast<uint32_t>(counter_block_[13]) << 16 |
                 static_cast<uint32_t>(counter_block_[14]) << 8 |
                 static_cast<uint32_t>(counter_block_[15]);
  ++ctr;
  counter_block_[12] = static_cast<uint8_t>((ctr >> 24) & 0xFF);
  counter_block_[13] = static_cast<uint8_t>((ctr >> 16) & 0xFF);
  counter_block_[14] = static_cast<uint8_t>((ctr >> 8) & 0xFF);
  counter_block_[15] = static_cast<uint8_t>(ctr & 0xFF);
  offset_ = 0;
}

void CtrCryptoStream::xorData(uint8_t* data, std::size_t size) {
  if (!initialized_) {
    throw std::runtime_error("CTR stream used before initialize");
  }

  for (std::size_t i = 0; i < size; ++i) {
    if (offset_ == keystream_block_.size()) {
      refill();
    }
    data[i] ^= keystream_block_[offset_++];
  }
}

}  // namespace nse_fo_exchange_sim
