/*
 * ===--- eccpem_read.c -----------------------------------------------------===
 *
 * This file is distributed under the MIT License. See LICENSE for details.
 *
 * AUTHOR: Artiom Baloian <artiom.baloian@nyu.edu>
 *
 * DESCRIPTION:
 * File provides functionality to read Elliptic Curve Cryptography (ECC) key pairs
 * from PEM formatted files. The functions in this file allow reading both private
 * and public keys from PEM files and converting them into binary format for use
 * in cryptographic operations.
 */

#include "eccpem_read.h"
#include "utils.h"

#include <stdio.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

/*
 * Function reads private key's PEM file and stores it in a given array as binary data.
 *
 * Arguments:
 * - privkey_file: PEM formatted file (extension is .pem) from which the private key
 *                 will be read and stored in an array as binary data.
 * - private_key: An array where the private key will be stored.
 * - key_size: Size of array. Run `$ openssl ecparam -list_curves` command to see
 *            the binary size of the specific cryptographic algorithm.
 *
 * Returns:
 * - 1 if reading PEM file and storing data to array was successful.
 * - 0 if it cannot open the provided PEM file, cannot read the provided PEM file,
 *     fails to convert EVP_PKEY to EC_KEY, or fails to convert bignum to binary.
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

  /* Get the private key as a BIGNUM */
  const BIGNUM* priv_key_bn = NULL;
  EC_KEY* ec_key = EVP_PKEY_get1_EC_KEY(pkey);
  if (ec_key == NULL) {
    EVP_PKEY_free(pkey);
    fprintf(stderr, "Failed to convert EVP_PKEY to EC_KEY.\n");
    return 0;
  }

  priv_key_bn = EC_KEY_get0_private_key(ec_key);
  if (priv_key_bn == NULL) {
    EVP_PKEY_free(pkey);
    EC_KEY_free(ec_key);
    fprintf(stderr, "Failed to get private key as BIGNUM.\n");
    return 0;
  }

  /* Clear the output buffer */
  memset(private_key, 0, key_size);

  /* Convert BIGNUM to binary */
  const int bn_size = BN_num_bytes(priv_key_bn);
  if (bn_size > key_size) {
    EVP_PKEY_free(pkey);
    EC_KEY_free(ec_key);
    fprintf(stderr, "Private key size is larger than provided buffer.\n");
    return 0;
  }

  if (BN_bn2bin(priv_key_bn, private_key) != bn_size) {
    EVP_PKEY_free(pkey);
    EC_KEY_free(ec_key);
    fprintf(stderr, "Failed to convert private key to binary.\n");
    return 0;
  }

  EVP_PKEY_free(pkey);
  EC_KEY_free(ec_key);

  return 1;
}



/*
 * Function reads public key's PEM file and stores it as compressed binary data.
 *
 * Arguments:
 * - pubkey_file: PEM formatted file (.pem extension) containing the public key
 * - public_key: Output buffer to store the compressed public key binary data
 * - compressed_key_size: Size of output buffer. For ECDSA compressed public keys,
 *                       this should be 33 bytes.
 *
 * Returns:
 * - 1 on success: Public key was read and stored successfully
 * - 0 on failure: Returns 0 if any of the following operations fail:
 *     - Invalid PEM file format or missing file
 *     - Invalid input parameters
 *     - Reading or parsing the PEM file
 *     - Converting key formats
 *     - Compressing the public key
 */
int ReadPublicKeyPemFile(const char* pubkey_file,
                         uint8_t public_key[],
                         const unsigned int compressed_key_size) {
  /* Validate input parameters */
  if (!VerifyPemFileFormat(pubkey_file)) {
    return 0;
  }

  if (public_key == NULL) {
    fprintf(stderr, "Public key output buffer cannot be NULL\n");
    return 0;
  }

  if (compressed_key_size == 0) {
    fprintf(stderr, "Invalid compressed key size. Expected 33 bytes for ECDSA "
                    "compressed public key\n");
    return 0;
  }

  /* Open and read the PEM file */
  FILE* pem_file = fopen(pubkey_file, "r");
  if (pem_file == NULL) {
    fprintf(stderr, "Failed to open public key PEM file\n");
    return 0;
  }

  EVP_PKEY* pkey = PEM_read_PUBKEY(pem_file, NULL, NULL, NULL);
  fclose(pem_file);

  if (pkey == NULL) {
    fprintf(stderr, "Failed to parse public key from PEM file\n");
    return 0;
  }

  /* Convert to EC key format */
  EC_KEY* ec_key = EVP_PKEY_get1_EC_KEY(pkey);
  if (ec_key == NULL) {
    EVP_PKEY_free(pkey);
    fprintf(stderr, "Failed to extract EC key from EVP_PKEY\n");
    return 0;
  }

  /* Set compressed point format */
  EC_KEY_set_conv_form(ec_key, POINT_CONVERSION_COMPRESSED);

  /* Convert to binary, preserving original buffer pointer */
  uint8_t* pub_copy = public_key;
  const int key_size = i2o_ECPublicKey(ec_key, &pub_copy);
  
  if (key_size != compressed_key_size) {
    EVP_PKEY_free(pkey);
    EC_KEY_free(ec_key);
    fprintf(stderr, "Compressed key size mismatch. Got %d bytes, expected %u\n",
            key_size, compressed_key_size);
    return 0;
  }

  /* Cleanup */
  EVP_PKEY_free(pkey);
  EC_KEY_free(ec_key);

  return 1;
}

