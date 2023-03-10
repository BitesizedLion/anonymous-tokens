// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "anonymous_tokens/cpp/crypto/crypto_utils.h"

#include <string>
#include <utility>
#include <vector>

#include "anonymous_tokens/cpp/crypto/constants.h"
#include "anonymous_tokens/cpp/crypto/status_utils.h"
#include <openssl/err.h>
#include <openssl/rsa.h>


namespace anonymous_tokens {

namespace internal {

BN_ULONG TOBN(BN_ULONG hi, BN_ULONG lo) {
  return ((BN_ULONG)(hi) << 32 | (lo));
}

// Approximation of sqrt(2) taken from
// //depot/google3/third_party/openssl/boringssl/src/crypto/fipsmodule/rsa/rsa_impl.c;l=997
const BN_ULONG kBoringSSLRSASqrtTwo[] = {
    TOBN(0x4d7c60a5, 0xe633e3e1), TOBN(0x5fcf8f7b, 0xca3ea33b),
    TOBN(0xc246785e, 0x92957023), TOBN(0xf9acce41, 0x797f2805),
    TOBN(0xfdfe170f, 0xd3b1f780), TOBN(0xd24f4a76, 0x3facb882),
    TOBN(0x18838a2e, 0xaff5f3b2), TOBN(0xc1fcbdde, 0xa2f7dc33),
    TOBN(0xdea06241, 0xf7aa81c2), TOBN(0xf6a1be3f, 0xca221307),
    TOBN(0x332a5e9f, 0x7bda1ebf), TOBN(0x0104dc01, 0xfe32352f),
    TOBN(0xb8cf341b, 0x6f8236c7), TOBN(0x4264dabc, 0xd528b651),
    TOBN(0xf4d3a02c, 0xebc93e0c), TOBN(0x81394ab6, 0xd8fd0efd),
    TOBN(0xeaa4a089, 0x9040ca4a), TOBN(0xf52f120f, 0x836e582e),
    TOBN(0xcb2a6343, 0x31f3c84d), TOBN(0xc6d5a8a3, 0x8bb7e9dc),
    TOBN(0x460abc72, 0x2f7c4e33), TOBN(0xcab1bc91, 0x1688458a),
    TOBN(0x53059c60, 0x11bc337b), TOBN(0xd2202e87, 0x42af1f4e),
    TOBN(0x78048736, 0x3dfa2768), TOBN(0x0f74a85e, 0x439c7b4a),
    TOBN(0xa8b1fe6f, 0xdc83db39), TOBN(0x4afc8304, 0x3ab8a2c3),
    TOBN(0xed17ac85, 0x83339915), TOBN(0x1d6f60ba, 0x893ba84c),
    TOBN(0x597d89b3, 0x754abe9f), TOBN(0xb504f333, 0xf9de6484),
};
const int kBoringSSLRSASqrtTwoLen = 32;

}  // namespace internal

absl::StatusOr<BnCtxPtr> GetAndStartBigNumCtx() {
  // Create context to be used in intermediate computation.
  BnCtxPtr bn_ctx = BnCtxPtr(BN_CTX_new());
  if (!bn_ctx.get()) {
    return absl::InternalError("Error generating bignum context.");
  }
  BN_CTX_start(bn_ctx.get());

  return bn_ctx;
}

absl::StatusOr<bssl::UniquePtr<BIGNUM>> NewBigNum() {
  bssl::UniquePtr<BIGNUM> bn(BN_new());
  if (!bn.get()) {
    return absl::InternalError("Error generating bignum.");
  }
  return bn;
}

absl::StatusOr<std::string> BignumToString(const BIGNUM& big_num,
                                           const size_t output_len) {
  std::vector<uint8_t> serialization(output_len);
  if (BN_bn2bin_padded(serialization.data(), serialization.size(), &big_num) !=
      kBsslSuccess) {
    return absl::InternalError(
        absl::StrCat("Function BN_bn2bin_padded failed: ", GetSslErrors()));
  }
  return std::string(std::make_move_iterator(serialization.begin()),
                     std::make_move_iterator(serialization.end()));
}

absl::StatusOr<bssl::UniquePtr<BIGNUM>> StringToBignum(
    const absl::string_view input_str) {
  ANON_TOKENS_ASSIGN_OR_RETURN(bssl::UniquePtr<BIGNUM> output, NewBigNum());
  if (!BN_bin2bn(reinterpret_cast<const uint8_t*>(input_str.data()),
                 input_str.size(), output.get())) {
    return absl::InternalError(
        absl::StrCat("Function BN_bin2bn failed: ", GetSslErrors()));
  }
  if (!output.get()) {
    return absl::InternalError("Function BN_bin2bn failed.");
  }
  return output;
}

std::string GetSslErrors() {
  std::string ret;
  ERR_print_errors_cb(
      [](const char* str, size_t len, void* ctx) -> int {
        static_cast<std::string*>(ctx)->append(str, len);
        return 1;
      },
      &ret);
  return ret;
}

absl::StatusOr<bssl::UniquePtr<BIGNUM>> GetRsaSqrtTwo(int x) {
  // Compute hard-coded sqrt(2).
  ANON_TOKENS_ASSIGN_OR_RETURN(bssl::UniquePtr<BIGNUM> sqrt2, NewBigNum());
  for (int i = internal::kBoringSSLRSASqrtTwoLen - 1; i >= 0; --i) {
    if (BN_add_word(sqrt2.get(), internal::kBoringSSLRSASqrtTwo[i]) != 1) {
      return absl::InternalError(absl::StrCat(
          "Cannot add word to compute RSA sqrt(2): ", GetSslErrors()));
    }
    if (i > 0) {
      if (BN_lshift(sqrt2.get(), sqrt2.get(), 64) != 1) {
        return absl::InternalError(absl::StrCat(
            "Cannot shift to compute RSA sqrt(2): ", GetSslErrors()));
      }
    }
  }

  // Check that hard-coded result is correct length.
  int sqrt2_bits = 64 * internal::kBoringSSLRSASqrtTwoLen;
  if (BN_num_bits(sqrt2.get()) != sqrt2_bits) {
    return absl::InternalError("RSA sqrt(2) is not correct length.");
  }

  // Either shift left or right depending on value x.
  if (sqrt2_bits > x) {
    if (BN_rshift(sqrt2.get(), sqrt2.get(), sqrt2_bits - x) != 1) {
      return absl::InternalError(
          absl::StrCat("Cannot rshift to compute 2^(x-1/2): ", GetSslErrors()));
    }
  } else {
    // Round up and be pessimistic about minimium factors.
    if (BN_add_word(sqrt2.get(), 1) != 1 ||
        BN_lshift(sqrt2.get(), sqrt2.get(), x - sqrt2_bits) != 1) {
      return absl::InternalError(absl::StrCat(
          "Cannot add/lshift to compute 2^(x-1/2): ", GetSslErrors()));
    }
  }

  // Check that 2^(x - 1/2) is correct length.
  if (BN_num_bits(sqrt2.get()) != x) {
    return absl::InternalError(
        "2^(x-1/2) is not correct length after shifting.");
  }

  return std::move(sqrt2);
}

absl::StatusOr<bssl::UniquePtr<BIGNUM>> ComputePowerOfTwo(int x) {
  ANON_TOKENS_ASSIGN_OR_RETURN(bssl::UniquePtr<BIGNUM> ret, NewBigNum());
  if (BN_set_bit(ret.get(), x) != 1) {
    return absl::InternalError(
        absl::StrCat("Unable to set bit to compute 2^x: ", GetSslErrors()));
  }
  if (!BN_is_pow2(ret.get()) || !BN_is_bit_set(ret.get(), x)) {
    return absl::InternalError(absl::StrCat("Unable to compute 2^", x, "."));
  }
  return ret;
}

absl::StatusOr<std::string> ComputeHash(absl::string_view input,
                                        const EVP_MD& hasher) {
  std::string digest;
  digest.resize(EVP_MAX_MD_SIZE);

  uint32_t digest_length = 0;
  if (EVP_Digest(input.data(), input.length(),
                 reinterpret_cast<uint8_t*>(&digest[0]), &digest_length,
                 &hasher, /*impl=*/nullptr) != 1) {
    return absl::InternalError(absl::StrCat(
        "Openssl internal error computing hash: ", GetSslErrors()));
  }
  digest.resize(digest_length);
  return digest;
}

}  // namespace anonymous_tokens

