#include <eccpem/eccpem.h>
#include <stdio.h>

int main() {

  const char* pubkey_file = "pub_key.pem";
  const char* privkey_file = "priv_key.pem";

  const char* ec_type = "secp256k1";

  const int error_code = CreateECCKeysPemFiles(ec_type, pubkey_file, privkey_file);
  if (error_code == 1) {
    printf("Generation of ECC key pairs was successful.\n");
  } else {
    printf("Generation of ECC key pairs failed.\n");
  }

  return 0;
}

