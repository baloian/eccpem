#include <eccpem/eccpem.h>
#include <iostream>
#include <string>

int main() {

  const std::string pubkey_file = "pub_key.pem";
  const std::string privkey_file = "priv_key.pem";

  const std::string ec_type = "secp256k1";

  const int error_code = CreateECCKeysPemFiles(ec_type.c_str(),
                                               pubkey_file.c_str(),
                                               privkey_file.c_str());
  if (error_code == 1) {
    std::cout << "Generation of ECC key pairs was successful.\n";
  } else {
    std::cout << "Generation of ECC key pairs filed.\n";
  }

  return 0;
}
