#include <iostream>
#include "anonymous_tokens/cpp/client/anonymous_tokens_rsa_bssa_client.h"
#include "anonymous_tokens/proto/anonymous_tokens.proto.h"
using namespace std;

int main() {
  string pubKey = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs+RnHhhqXK44qwNO4B6R\nVU6UitRIOVrLWsPiBMDtrFj5VXLcqB/2yTFDY3fag9V4Cr4c/qFW9TWu/GqaAN/z\n0ZmSEvxTxTII2LcNf/3GEkMjpIbcHc5nLMx6mUhcPhqov2rROtoeaIYKJN1/CLz0\nBpNLU5DhttDmL5GCAemebApYyi3vaZ7IRq2p6dPgu2X8oqX/hM2HCLaeGonkNuqW\nf3AvdEYwQUAI+YVsoVLwtyOtBuiqkW5yPcD9zB0sW0LMIb1RiKqcbolCDItDwNLw\nlQKM80cGfaFIrp+gcj4pg627MicjcmP9O84si7cbNyyq9eursvC3+UvkYhq7fLO4\ntQIDAQAB\n-----END PUBLIC KEY-----\n";

auto bssa_client = AnonymousTokensRsaBssaClient::Create(
        pubKey);

  cout << "Hello World!" << endl;
}
