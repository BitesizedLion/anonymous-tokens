#ifndef ANONYMOUS_TOKENS_CPP_CRYPTO_RSA_BLINDER_H_
#define ANONYMOUS_TOKENS_CPP_CRYPTO_RSA_BLINDER_H_

#include <memory>
#include <string>

#include "anonymous_tokens/cpp/crypto/blinder.h"
#include "anonymous_tokens/cpp/crypto/crypto_utils.h"
#include "anonymous_tokens/proto/anonymous_tokens.pb.h"


namespace anonymous_tokens {

// RsaBlinder is able to blind a token, and unblind it after it has been signed.
class RsaBlinder : public Blinder {
 public:
  static absl::StatusOr<std::unique_ptr<RsaBlinder>> New(
      const RSABlindSignaturePublicKey& public_key,
      absl::string_view public_metadata = "");

  // Blind `message` using n and e derived from an RSA public key.
  // `message` will first be encoded with the EMSA-PSS operation.
  // This encoding operation matches that which is used by RsaVerifier.
  absl::StatusOr<std::string> Blind(absl::string_view message) override;

  // Unblinds `blind_signature`.
  absl::StatusOr<std::string> Unblind(
      absl::string_view blind_signature) override;

  // Verifies a signature.
  absl::Status Verify(absl::string_view signature, absl::string_view message);

 private:
  // Use `New` to construct
  RsaBlinder(bssl::UniquePtr<BIGNUM> r, bssl::UniquePtr<BIGNUM> r_inv_mont,
             bssl::UniquePtr<RSA> public_key,
             bssl::UniquePtr<BN_MONT_CTX> mont_n, const EVP_MD* sig_hash_,
             const EVP_MD* mgf1_hash_, int32_t salt_length_,
             absl::string_view public_metadata);

  const bssl::UniquePtr<BIGNUM> r_;
  // r^-1 mod n in the Montgomery domain
  const bssl::UniquePtr<BIGNUM> r_inv_mont_;
  const bssl::UniquePtr<RSA> public_key_;
  const bssl::UniquePtr<BN_MONT_CTX> mont_n_;
  const EVP_MD* sig_hash_;   // Owned by BoringSSL.
  const EVP_MD* mgf1_hash_;  // Owned by BoringSSL.
  const int32_t salt_length_;
  const absl::string_view public_metadata_;

  std::string message_;
  BlinderState blinder_state_;
};

}  // namespace anonymous_tokens


#endif  // ANONYMOUS_TOKENS_CPP_CRYPTO_RSA_BLINDER_H_
