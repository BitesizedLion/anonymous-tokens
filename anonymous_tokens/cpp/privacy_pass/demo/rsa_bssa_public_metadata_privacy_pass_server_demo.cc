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

// To run this binary from this directory use:
// bazel run -c opt :rsa_bssa_public_metadata_privacy_pass_server_demo
// --cxxopt='-std=c++17'

#include <iostream>
#include <ostream>
#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "anonymous_tokens/cpp/crypto/crypto_utils.h"
#include "anonymous_tokens/cpp/privacy_pass/token_encodings.h"
#include "anonymous_tokens/cpp/testing/utils.h"
#include <openssl/base.h>

absl::Status RunDemo() {
  // Construct RSA private key with a strong rsa modulus.
  auto [_, test_rsa_private_key] =
      anonymous_tokens::GetStrongTestRsaKeyPair2048();
  absl::StatusOr<bssl::UniquePtr<RSA>> rsa_private_key =
      anonymous_tokens::CreatePrivateKeyRSA(
          test_rsa_private_key.n, test_rsa_private_key.e,
          test_rsa_private_key.d, test_rsa_private_key.p,
          test_rsa_private_key.q, test_rsa_private_key.dp,
          test_rsa_private_key.dq, test_rsa_private_key.crt);
  if (!rsa_private_key.ok()) {
    return rsa_private_key.status();
  }

  // Wait for token request.
  std::cout << "Waiting for Token Type DA7A, Extended Token Request (in "
               "hexadecimal string format):"
            << std::endl;

  std::string extended_token_request_hex_str;
  std::string extended_token_request_str;

  std::cin >> extended_token_request_hex_str;
  extended_token_request_str =
      absl::HexStringToBytes(extended_token_request_hex_str);

  absl::StatusOr<anonymous_tokens::ExtendedTokenRequest>
      extended_token_request =
          anonymous_tokens::UnmarshalExtendedTokenRequest(
              extended_token_request_str);
  if (!extended_token_request.ok()) {
    return extended_token_request.status();
  }

  // Sign token request.
  absl::StatusOr<std::string> encoded_extensions =
      anonymous_tokens::EncodeExtensions(
          (*extended_token_request).extensions);
  if (!encoded_extensions.ok()) {
    return encoded_extensions.status();
  }

  absl::StatusOr<std::string> signature =
      anonymous_tokens::TestSignWithPublicMetadata(
          (*extended_token_request).request.blinded_token_request,
          /*public_metadata=*/*encoded_extensions, *rsa_private_key.value(),
          /*use_rsa_public_exponent=*/false);
  if (!signature.ok()) {
    return signature.status();
  }
  std::cout
      << "Token Type DA7A, Token Response (in hexadecimal string format):\n"
      << absl::BytesToHexString(signature.value()) << std::endl;

  return absl::OkStatus();
}

using namespace std;
#include "anonymous_tokens/cpp/client/anonymous_tokens_rsa_bssa_client.h"

using ::anonymous_tokens::AnonymousTokensRsaBssaClient;
using ::anonymous_tokens::AnonymousTokensSignRequest;
using ::anonymous_tokens::AnonymousTokensSignResponse;
using ::anonymous_tokens::PlaintextMessageWithPublicMetadata;
using ::anonymous_tokens::RSABlindSignatureTokenWithInput;
using ::anonymous_tokens::RSABlindSignaturePublicKey;
using ::anonymous_tokens::AT_HASH_TYPE_SHA384;
using ::anonymous_tokens::AT_MGF_SHA384;
using ::anonymous_tokens::AT_MESSAGE_MASK_CONCAT;
using ::anonymous_tokens::AnonymousTokensUseCase_Name;
using ::anonymous_tokens::RSAPublicKey;
using ::anonymous_tokens::RSAPrivateKey;

constexpr char kAlphabet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

    static uint8_t GetRandomUInt8() {
        // Create a random number generator
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint16_t> dis(0, 255); // Distribution for uint8_t

        // Generate a random number and return it as uint8_t
        return static_cast<uint8_t>(dis(gen));
    }

std::string RandomUTF8String(size_t len, absl::string_view alphabet) {
  std::string result(len, '\0');
  const int k = alphabet.size();
  for (char& c : result) {
    auto idx = GetRandomUInt8();
    c = alphabet[idx % k];
  }
  // Add a structure, for more context
  return absl::StrCat("blind:", result);
}

// void BytesFromUint64(uint64_t fp, std::string* key) {
//     uint64_t norder = htobe64(fp);
//     const char* bytes = reinterpret_cast<const char*>(&norder);
//     key->assign(bytes, sizeof(norder));
// }

// // Convenient form of KeyFromUint64.
// std::string Uint64ToBytes(uint64_t fp) {
//   std::string key;
//   BytesFromUint64(fp, &key);
//   return key;
// }

// // Converts an 8-byte string key (typically generated by Uint64ToKey or
// // KeyFromUint64) into a uint64_t value
// uint64_t BytesToUint64(absl::string_view key) {
//   uint64_t value;
//   // DCHECK_EQ(key.size(), sizeof(value));
//   memcpy(&value, key.data(), sizeof(value));
//   return htobe64(value);
// }

#include "absl/strings/escaping.h"

int main(int argc, char** argv) {
  cout << "1" << endl;

  RSAPublicKey rsa_public_key;
  std::string shitfuck = "CoAE57jQnigNEsUYdeMGHwRjKX/PrSQs0daOJIhMIXskT+9U0n1Cap1khODnnLTou/RmcfLQFRwjOM0/a0WHzez9srOgYc/69lklhMi0hLrIn2OwVwJAXAl7syIyOQSFrnlVBCB1XA6kvx10eeMe8XMQ2n8s5UERzgUzB77WEWMYMSaE4l7TQEaaXL/GH7XrhgQ9FUo5T0TQ+iWisMidA3Jf+jbeXmG42PxzyK3/UC6su6HVMbGCFW2sXQI+I/Zze7Mlt79VFeqD53xChyqpUOELG3rO+1N/l/Vuvp1Wwlt+9UTiTRLe/1DEzXPJGfFim2OnTazmn01Q6m8cTsWBbmflFvIR62S9dCiPaZpTWlqz1URLBkVXkONBOVMqooyPL9CFTseoKI3EgkgLK2JPxfAx3IVsqHA0rSfHNnNYfESEQ/SF+CoyzXaDpVA/VL6CfS6VgRkqI2L4wYd20r7MYMX4zIzw6NZnRiZ065Nw1MW/qN0g7837lZ0cnGH7sCtVVeu6gjYQQtahnjl5mKfUTm5INQngbzK77cUZ/w9/3OPboDCt/vkpNjbuTe+4qNUum39M3xJfCcRAseaOFbQjDzXrJKp/9vmJsmfmWMQieozgsC6zRIjNWepAovI+R4YICE+SzSaXKKgvttAIZOyaRuMzTWIy6toD8UFMbUMv/dcfZWUSAwEAAQ==";
  std::string decoded_string;
  absl::Base64Unescape(shitfuck, &decoded_string);
  bool test = rsa_public_key.ParseFromString(decoded_string);

  cout << test << endl;
  cout << rsa_public_key.n() << endl;

  RSABlindSignaturePublicKey public_key;
  public_key.set_key_version(55);
  cout << "3" << endl;
  public_key.set_serialized_public_key(decoded_string);
  cout << "4" << endl;
  public_key.set_sig_hash_type(AT_HASH_TYPE_SHA384);
  cout << "5" << endl;
  public_key.set_mask_gen_function(AT_MGF_SHA384);
  cout << "6" << endl;
  public_key.set_salt_length(48);
  cout << "7" << endl;
  public_key.set_key_size(512);
  cout << "8" << endl;
  public_key.set_use_case("PROVABLY_PRIVATE_NETWORK");
  cout << "9" << endl;
  public_key.set_message_mask_type(AT_MESSAGE_MASK_CONCAT);
  cout << "10" << endl;
  public_key.set_message_mask_size(32);
  public_key.set_public_metadata_support(true);
  
  auto bssa_client = AnonymousTokensRsaBssaClient::Create(public_key);
  cout << "11" << endl;

    // Create plaintext tokens.
    // Client blinds plaintext tokens (random 32-byte strings) in CreateRequest.
    std::vector<PlaintextMessageWithPublicMetadata> plaintext_tokens;
    PlaintextMessageWithPublicMetadata plaintext_message;
    //  Get random UTF8 32 byte string prefixed with "blind:".
    plaintext_message.set_plaintext_message(RandomUTF8String(32, kAlphabet));
    uint64_t fingerprint = 0;
    // absl::Status fingerprint_status = FingerprintPublicMetadata(
    //     get_initial_data_response_.public_metadata_info().public_metadata(),
    //     &fingerprint);
    // if (!fingerprint_status.ok()) {
    //   SetState(State::kUnauthenticated);
    //   LOG(ERROR) << "Failed to fingerprint public metadata: "
    //              << fingerprint_status;
    //   return;
    // }

    plaintext_message.set_public_metadata(Uint64ToBytes(fingerprint));
    plaintext_tokens.push_back(plaintext_message);
    cout << public_key.serialized_public_key() << endl;

    cout << "12" << endl;
    auto at_sign_request = bssa_client.value()->CreateRequest(plaintext_tokens);
    cout << "13" << endl;
    if (!at_sign_request.ok()) {
      // SetState(State::kUnauthenticated);
      // LOG(ERROR)
      //     << "HandleInitialDataResponse Failed to create AT Sign Request: "
      //     << at_sign_request.status();
      return 0;
    }
    std::unique_ptr<AnonymousTokensRsaBssaClient> bssa_client_ = *std::move(bssa_client);
    AnonymousTokensSignRequest at_sign_request_ = at_sign_request.value();


  cout << "Hello World!" << endl;

  return 0;
}
