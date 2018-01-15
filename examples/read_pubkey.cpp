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

  const std::string pub_file = "pub_key.pem";

  const unsigned int compressed_size = 33;
  uint8_t* pub_key = new uint8_t[compressed_size];

  const int error_code = ReadPublicKeyPemFile(pub_file.c_str(), pub_key, compressed_size);
  if (error_code == 1) {
    std::cout << "Reading public key from PEM file was successful.\n";
    const std::string hex_pubkey = ArrayToHexString(pub_key, compressed_size);
    std::cout << "Compressed public key in hex format: " << hex_pubkey << "\n";
  } else {
    std::cerr << "Reading public key from PEM file filed.\n";
  }

  delete []pub_key;

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

