#include <eccpem/eccpem.h>
#include <iostream>
#include <string>
#include <stdint.h>

// Function converts uint8_t type of array to hex string.
//
// Arguments:
// - array: Input array.
// - size: Size of array.
//
// Returns:
// - Converted string.
std::string ArrayToHexString(const uint8_t array[], const unsigned int size);


int main() {

  const std::string privkey_file = "priv_key.pem";

  const unsigned int size = 32;
  uint8_t* private_key = new uint8_t[size];

  const int error_code = ReadPrivateKeyPemFile(privkey_file.c_str(), private_key, size);
  if (error_code == 1) {
    std::cout << "Reading private key from PEM file was successful.\n";
    const std::string hex_privkey = ArrayToHexString(private_key, size);
    std::cout << "Private key in hex format: " << hex_privkey << "\n";
  } else {
    std::cerr << "Reading private key from PEM file filed.\n";
  }

  delete []private_key;

  return 0;
}



// Function converts uint8_t type of array to hex string.
//
// Arguments:
// - array: Input array.
// - size: Size of array.
//
// Returns:
// - Converted string.
std::string ArrayToHexString(const uint8_t array[], const unsigned int size) {
  // Two digits for per uint8_t array character.
  std::string hex_str(2 * size, '\0');

  // If we devide value of uint8_t array character to 16 (char/16 or char%16)
  // the result should be one of hex values.
  // Note that we support only uppercase letters. For example, 12fe is not valid
  // despite it is an hex format, it must be 12FE.
  const std::string hex_code = "0123456789ABCDEF";

  const short int base = 16;
  unsigned int idx = 0;
  for (std::size_t i = 0; i < size; i++) {
    hex_str[idx++] = hex_code[(array[i] / base)];
    hex_str[idx++] = hex_code[(array[i] % base)];
  }

  return hex_str;
}

