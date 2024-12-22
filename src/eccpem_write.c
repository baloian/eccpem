/*
 * ===--- eccpem_write.c ----------------------------------------------------===
 *
 * This file is distributed under the MIT License. See LICENSE for details.
 *
 * AUTHOR: Artiom Baloian <artiom.baloian@nyu.edu>
 *
 * DESCRIPTION:
 * File provides functionality to generate Elliptic Curve Cryptography key pairs,
 * write keys to PEM formatted files, and verify file formats.
 */

#include "eccpem_write.h"
#include "utils.h"

#include <stdio.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

/*
 * Function generates an Elliptic Curve Cryptography (ECC) key pair and writes the
 * public and private keys to separate PEM formatted files. If the specified files
 * already exist, they will be overwritten. Otherwise, new files will be created.
 *
 * Arguments:
 * - ec_type: The type of elliptic curve to use for key generation. Must be a valid
 *            curve name as listed by the command: openssl ecparam -list_curves
 * - pubkey_file: Path to the PEM file (.pem extension) where the public key will
 *                be written
 * - privkey_file: Path to the PEM file (.pem extension) where the private key will
 *                 be written
 *
 * Returns:
 * - 1 on success: Key pair was generated and written to files successfully
 * - 0 on failure: Returns 0 if any of the following operations fail:
 *     - Creating the OpenSSL EC_KEY object
 *     - Generating the EC key pair
 *     - Allocating or configuring the EVP_PKEY structure
 *     - Writing either the public or private key to their respective PEM files
 */
int CreateECCKeysPemFiles(const char* ec_type,
                          const char* pubkey_file,
                          const char* privkey_file) {
  /* Sanity checking of arguments. */
  if (ec_type == NULL) {
    fprintf(stderr, "Elliptic Curve type cannot be NULL. "
            "Run 'openssl ecparam -list_curves' command to list EC types.");
    return 0;
  }

  /* Verify both key files have .pem extension */
  if (!VerifyPemFileFormat(pubkey_file) || !VerifyPemFileFormat(privkey_file)) {
    return 0;
  }

  /* Create a new EVP_PKEY context for key generation */
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
  if (ctx == NULL) {
    fprintf(stderr, "Creating EVP_PKEY_CTX failed.\n");
    return 0;
  }

  /* Initialize key generation */
  if (EVP_PKEY_keygen_init(ctx) <= 0) {
    fprintf(stderr, "Initializing key generation failed.\n");
    EVP_PKEY_CTX_free(ctx);
    return 0;
  }

  /* Set the EC curve by name */
  if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, OBJ_txt2nid(ec_type)) <= 0) {
    fprintf(stderr, "Setting EC curve parameters failed.\n");
    EVP_PKEY_CTX_free(ctx);
    return 0;
  }

  /* Generate the key pair */
  EVP_PKEY *pkey = NULL;
  if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
    fprintf(stderr, "Generating EC key pair failed.\n");
    EVP_PKEY_CTX_free(ctx);
    return 0;
  }

  /* Write private and public keys' (binary data) in PEM format. */
  if (!WriteKeysToPEMFiles(pkey, pubkey_file, privkey_file)) {
    fprintf(stderr, "Writing private and public keys in PEM format files failed.\n");
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return 0;
  }

  /* Free memory */
  EVP_PKEY_free(pkey);
  EVP_PKEY_CTX_free(ctx);

  return 1;
}



/*
 * Function writes private and public keys to PEM formatted files. The keys are
 * represented by an EVP_PKEY structure. If the target files already exist, they
 * will be overwritten. If they don't exist, new files will be created.
 *
 * Arguments:
 * - pkey: EVP_PKEY structure containing both the private and public keys
 * - pubkey_file: Path where the public key will be written in PEM format (.pem extension)
 * - privkey_file: Path where the private key will be written in PEM format (.pem extension)
 *
 * Returns:
 * - 1 if both PEM files were written successfully
 * - 0 if creating or writing to either PEM file failed, or if any other error occurred
 */
static int WriteKeysToPEMFiles(EVP_PKEY* pkey,
                               const char* pubkey_file,
                               const char* privkey_file) {
  /* Write private key to file */
  FILE* privkey_fp = fopen(privkey_file, "w");
  if (privkey_fp == NULL) {
    fprintf(stderr, "Unable to open private key file for writing.\n");
    return 0;
  }

  if (!PEM_write_PrivateKey(privkey_fp, pkey, NULL, NULL, 0, NULL, NULL)) {
    fprintf(stderr, "Error writing private key data in PEM format.\n");
    fclose(privkey_fp);
    return 0;
  }
  fclose(privkey_fp);

  /* Write public key to file */
  FILE* pubkey_fp = fopen(pubkey_file, "w");
  if (pubkey_fp == NULL) {
    fprintf(stderr, "Unable to open public key file for writing.\n");
    return 0;
  }

  if (!PEM_write_PUBKEY(pubkey_fp, pkey)) {
    fprintf(stderr, "Error writing public key data in PEM format.\n");
    fclose(pubkey_fp);
    return 0;
  }
  fclose(pubkey_fp);
  return 1;
}

