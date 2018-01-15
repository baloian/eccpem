/*
 * ===--- eccpem_read.h -----------------------------------------------------===
 *
 * This file is distributed under the MIT License. See LICENSE for details.
 *
 * AUTHOR: Artiom Baloian <artiom.baloian@nyu.edu>
 *
 * DESCRIPTION:
 * File provides functionality to read Elliptic Curve Cryptography key pairs
 * from PEM formatted files.
 */

#include "eccpem_read.h"
#include "utils.h"

#include <stdio.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

/*
 * Function reads private key's pem file and stores it in a given array as a
 * binary data.
 *
 * Arguments:
 * - privkey_file: PEM formatted file (extension is .pem) from where it is going
 *                 to be read private key and store in an array as a binary data.
 * - private_key: An array where is going to be stored private key.
 * - key_size: Size of array. Run $ openssl ecparam -list_curves command in
 *             order to see binary size of specific crypto algorithm.
 *
 *
 * Returns:
 * - 1 if readind pem file and storing data to array was successful.
 * - 0 if it cannot open provided PEM file or cannot read provided PEM file
 *     or fails to convert EVP_PKEY to EC_KEY or fails to convert bignum to
 *     binary.
 */
int ReadPrivateKeyPemFile(const char* privkey_file,
                          uint8_t private_key[],
                          const unsigned int key_size) {

  /* Sanity checking of arguments. */
  const int error_code = VerifyPemFileFormat(privkey_file);
  if (error_code == 0) {
    return 0;
  }

  if (private_key == NULL) {
    fprintf(stderr, "Private key's array cannot be null.\n");
    return 0;
  }

  if (key_size == 0) {
    fprintf(stderr, "Private key's array size cannot be null. "
                    "Check it using openssl ecparam -list_curves command.\n");
    return 0;
  }


  FILE* pem_file = fopen(privkey_file, "r");
  if (pem_file == NULL) {
    fprintf(stderr, "Unable to open private key's pem file or it does not exist.\n");
    return 0;
  }

  EVP_PKEY* pkey = PEM_read_PrivateKey(pem_file, NULL, NULL, NULL);
  if (pkey == NULL) {
    fclose(pem_file);
    fprintf(stderr, "Failed to read PEM format private key.\n");
    return 0;
  }

  /* We do not need pem file anymore. */
  fclose(pem_file);

  /*
   * Extract EC-specifics from the key, it returns the referenced key in pkey
   * or NULL if the key is not of the correct type.
   * We should do it because EC_KEY_free() decrements the reference count for
   * the EC_KEY object, and if it has dropped to zero then frees the memory
   * associated with it.
   */
  EC_KEY* ec_key = EVP_PKEY_get1_EC_KEY(pkey);
  if (ec_key == NULL) {
    EVP_PKEY_free(pkey);
    fprintf(stderr, "Failed to convert EVP_PKEY to EC_KEY.\n");
    return 0;
  }

  /* At first we should get big number and then convert it to binary data. */
  BIGNUM* bn_privkey = BN_new();
  if (bn_privkey == NULL) {
    EVP_PKEY_free(pkey);
    EC_KEY_free(ec_key);
    fprintf(stderr, "Failed to allocate and initialize a BIGNUM structure.\n");
    return 0;
  }

  memcpy(bn_privkey, EC_KEY_get0_private_key(ec_key), sizeof(BIGNUM));

  bzero(private_key, key_size);

  const int ret_value = BN_bn2bin(bn_privkey, private_key);
  if (ret_value == 0) {
    EVP_PKEY_free(pkey);
    EC_KEY_free(ec_key);
    fprintf(stderr, "Failed to convert bignum to binary.\n");
  }

  EVP_PKEY_free(pkey);
  EC_KEY_free(ec_key);

  return 1;
}



/*
 * Function reads public key's pem file and stores it in a given array as a
 * binary data.
 *
 * Arguments:            
 * - pubkey_file: PEM formatted file (extension is .pem) from where it is going
 *                to be read public key and store in an array as a binary data.
 * - public_key: An array where is going to be stored compressed public key.
 * - key_size: Size of array. Basically compressed public key size is 33 byte.
 *
 *
 * Returns:
 * - 1 if readind pem file and storing data to array was successful.
 * - 0 if it cannot open provided PEM file or cannot read provided PEM file
 *     or fails to convert EVP_PKEY to EC_KEY or files to read compressed EC
 *     public key.
 */
int ReadPublicKeyPemFile(const char* pubkey_file,
                         uint8_t public_key[],
                         const unsigned int compressed_key_size) {

  /* Sanity checking of arguments. */
  const int error_code = VerifyPemFileFormat(pubkey_file);
  if (error_code == 0) {
    return 0;
  }

  if (public_key == NULL) {
    fprintf(stderr, "Public key's array cannot be null.\n");
    return 0;
  }

  if (compressed_key_size == 0) {
    fprintf(stderr, "Public key's array size cannot be null. "
                    "Basically compressed key size of ECDSA public key is 33.\n");
    return 0;
  }


  FILE* pem_file = fopen(pubkey_file, "r");
  if (pem_file == NULL) {
    fprintf(stderr, "Unable to open public key's pem file or it does not exist.\n");
    return 0;
  }

  EVP_PKEY* pkey = PEM_read_PUBKEY(pem_file, NULL, NULL, NULL);
  if (pkey == NULL) {
    fclose(pem_file);
    fprintf(stderr, "Failed to read PEM format public key.\n");
    return 0;
  }

  /* We do not need pem file anymore. */
  fclose(pem_file);

  /*
   * Extract EC-specifics from the key, it returns the referenced key in pkey
   * or NULL if the key is not of the correct type.
   * We should do it because EC_KEY_free() decrements the reference count for
   * the EC_KEY object, and if it has dropped to zero then frees the memory
   * associated with it.
   */
  EC_KEY* ec_key = EVP_PKEY_get1_EC_KEY(pkey);
  if (ec_key == NULL) {
    EVP_PKEY_free(pkey);
    fprintf(stderr, "Failed to convert EVP_PKEY to EC_KEY.\n");
    return 0;
  }

  EC_KEY_set_conv_form(ec_key, POINT_CONVERSION_COMPRESSED);

  /*
   * Convert public key to compressed format and store it in public_key array.
   * i2o_ECPublicKey alters the input pointer, save your original pointer.
   */
  uint8_t* pub_copy = public_key;
  const int key_size = i2o_ECPublicKey(ec_key, &pub_copy);
  if (key_size != compressed_key_size) {
    EVP_PKEY_free(pkey);
    EC_KEY_free(ec_key);
    fprintf(stderr, "Failed to read compressed EC public key.\n");
    return 0;
  }

  /* Free memory. */
  EVP_PKEY_free(pkey);
  EC_KEY_free(ec_key);

  return 1;
}

