#include "anonymous_tokens/cpp/crypto/public_metadata_crypto_utils.h"

#include <cmath>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "anonymous_tokens/cpp/crypto/constants.h"
#include "anonymous_tokens/cpp/crypto/crypto_utils.h"
#include "anonymous_tokens/cpp/crypto/status_utils.h"
#include "anonymous_tokens/proto/anonymous_tokens.pb.h"
#include <openssl/hkdf.h>
#include <openssl/rsa.h>


namespace anonymous_tokens {

namespace public_metadata_crypto_utils_internal {

absl::StatusOr<bssl::UniquePtr<BIGNUM>> PublicMetadataHashWithHKDF(
    absl::string_view input, absl::string_view rsa_modulus_str,
    size_t out_len_bytes) {
  const EVP_MD* evp_md_sha_384 = EVP_sha384();
  // append 0x00 to input
  std::vector<uint8_t> input_buffer(input.begin(), input.end());
  input_buffer.push_back(0x00);
  std::string out_e;
  // We set the out_e size beyond out_len_bytes so that out_e bytes are
  // indifferentiable from truly random bytes even after truncations.
  //
  // Expanding to 16 more bytes is sufficient.
  // https://cfrg.github.io/draft-irtf-cfrg-hash-to-curve/draft-irtf-cfrg-hash-to-curve.html#name-hashing-to-a-finite-field
  const size_t hkdf_output_size = out_len_bytes + 16;
  out_e.resize(hkdf_output_size);
  // The modulus is used as salt to ensure different outputs for same metadata
  // and different modulus.
  if (HKDF(reinterpret_cast<uint8_t*>(out_e.data()), hkdf_output_size,
           evp_md_sha_384, input_buffer.data(), input_buffer.size(),
           reinterpret_cast<const uint8_t*>(rsa_modulus_str.data()),
           rsa_modulus_str.size(),
           reinterpret_cast<const uint8_t*>(kHkdfPublicMetadataInfo.data()),
           kHkdfPublicMetadataInfoSizeInBytes) != kBsslSuccess) {
    return absl::InternalError("HKDF failed in public_metadata_crypto_utils");
  }
  // Truncate out_e to out_len_bytes
  out_e.resize(out_len_bytes);
  ANON_TOKENS_ASSIGN_OR_RETURN(bssl::UniquePtr<BIGNUM> out,
                               StringToBignum(out_e));
  return std::move(out);
}

}  // namespace public_metadata_crypto_utils_internal

absl::StatusOr<bssl::UniquePtr<BIGNUM>> PublicMetadataExponent(
    const BIGNUM& n, absl::string_view public_metadata) {
  // Check modulus length.
  if (BN_num_bits(&n) % 2 == 1) {
    return absl::InvalidArgumentError(
        "Strong RSA modulus should be even length.");
  }
  int modulus_bytes = BN_num_bytes(&n);
  // The integer modulus_bytes is expected to be a power of 2.
  int prime_bytes = modulus_bytes / 2;

  ANON_TOKENS_ASSIGN_OR_RETURN(std::string rsa_modulus_str,
                               BignumToString(n, modulus_bytes));

  // Get HKDF output of length prime_bytes.
  ANON_TOKENS_ASSIGN_OR_RETURN(
      bssl::UniquePtr<BIGNUM> exponent,
      public_metadata_crypto_utils_internal::PublicMetadataHashWithHKDF(
          public_metadata, rsa_modulus_str, prime_bytes));

  // We need to generate random odd exponents < 2^(primes_bits - 2) where
  // prime_bits = prime_bytes * 8. This will guarantee that the resulting
  // exponent is coprime to phi(N) = 4p'q' as 2^(prime_bits - 2) < p', q' <
  // 2^(prime_bits - 1).
  //
  // To do this, we can truncate the HKDF output (exponent) which is prime_bits
  // long, to prime_bits - 2, by clearing its top two bits. We then set the
  // least significant bit to 1. This way the final exponent will be less than
  // 2^(primes_bits - 2) and will always be odd.
  if (BN_clear_bit(exponent.get(), (prime_bytes * 8) - 1) != kBsslSuccess ||
      BN_clear_bit(exponent.get(), (prime_bytes * 8) - 2) != kBsslSuccess ||
      BN_set_bit(exponent.get(), 0) != kBsslSuccess) {
    return absl::InvalidArgumentError(absl::StrCat(
        "Could not clear the two most significant bits and set the least "
        "significant bit to zero: ",
        GetSslErrors()));
  }
  // Check that exponent is small enough to ensure it is coprime to phi(n).
  if (BN_num_bits(exponent.get()) >= (8 * prime_bytes - 1)) {
    return absl::InternalError("Generated exponent is too large.");
  }

  return std::move(exponent);
}

absl::StatusOr<bssl::UniquePtr<BIGNUM>> ComputeFinalExponentUnderPublicMetadata(
    const BIGNUM& n, const BIGNUM& e, absl::string_view public_metadata) {
  ANON_TOKENS_ASSIGN_OR_RETURN(bssl::UniquePtr<BIGNUM> md_exp,
                               PublicMetadataExponent(n, public_metadata));
  ANON_TOKENS_ASSIGN_OR_RETURN(BnCtxPtr bn_ctx, GetAndStartBigNumCtx());
  // new_e=e*md_exp
  ANON_TOKENS_ASSIGN_OR_RETURN(bssl::UniquePtr<BIGNUM> new_e, NewBigNum());
  if (BN_mul(new_e.get(), md_exp.get(), &e, bn_ctx.get()) != 1) {
    return absl::InternalError(
        absl::StrCat("Unable to multiply e with md_exp: ", GetSslErrors()));
  }
  return std::move(new_e);
}

absl::StatusOr<bssl::UniquePtr<RSA>> RSAPublicKeyToRSAUnderPublicMetadata(
    const RSAPublicKey& public_key, absl::string_view public_metadata) {
  ANON_TOKENS_ASSIGN_OR_RETURN(bssl::UniquePtr<BIGNUM> rsa_modulus,
                               StringToBignum(public_key.n()));
  ANON_TOKENS_ASSIGN_OR_RETURN(bssl::UniquePtr<BIGNUM> old_e,
                               StringToBignum(public_key.e()));
  bssl::UniquePtr<BIGNUM> new_e;
  if (!public_metadata.empty()) {
    // Final exponent under Public metadata
    ANON_TOKENS_ASSIGN_OR_RETURN(
        new_e, ComputeFinalExponentUnderPublicMetadata(
                   *rsa_modulus.get(), *old_e.get(), public_metadata));
  } else {
    new_e = std::move(old_e);
  }
  // Convert to OpenSSL RSA.
  bssl::UniquePtr<RSA> rsa_public_key(RSA_new());
  if (!rsa_public_key.get()) {
    return absl::InternalError(
        absl::StrCat("RSA_new failed: ", GetSslErrors()));
  } else if (RSA_set0_key(rsa_public_key.get(), rsa_modulus.get(),
                          new_e.get(), nullptr) != kBsslSuccess) {
    return absl::InternalError(
        absl::StrCat("RSA_set0_key failed: ", GetSslErrors()));
  }
  rsa_modulus.release();
  new_e.release();
  return std::move(rsa_public_key);
}

}  // namespace anonymous_tokens

