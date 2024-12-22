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

  int error_code = VerifyPemFileFormat(pubkey_file);
  if (error_code == 0) {
    return 0;
  }

  error_code = VerifyPemFileFormat(privkey_file);
  if (error_code == 0) {
    return 0;
  }

  /* Initialize openssl functions. */
  OpenSSL_add_all_algorithms();

  /* Create a EC key structure, setting the group type from NID. */
  const int ecc_group_ty = OBJ_txt2nid(ec_type);
  EC_KEY* ec_key = EC_KEY_new_by_curve_name(ecc_group_ty);
  if (ec_key == NULL) {
    fprintf(stderr, "Creating a new OpenSSL EC_KEY object failed.\n");
    return 0;
  }

  /* For certificate signing, we use  the OPENSSL_EC_NAMED_CURVE flag. */
  EC_KEY_set_asn1_flag(ec_key, OPENSSL_EC_NAMED_CURVE);

  /*
   * Generates a new public and private key for the supplied ec_key object.
   * ec_key must have an EC_GROUP object associated with it before calling
   * this function.
   */
  error_code = EC_KEY_generate_key(ec_key);
  if (error_code == 0) {
    fprintf(stderr, "Generating a new EC public and private key failed.\n");
    EC_KEY_free(ec_key);
    return 0;
  }

  /*
   * Converting the EC key into a EVP_PKEY structure in order to handle the key
   * just like any other key pair.
   */
  EVP_PKEY* pkey = EVP_PKEY_new();
  if (pkey == NULL) {
    fprintf(stderr, "Generating the newly allocated EVP_PKEY failed.\n");
    EC_KEY_free(ec_key);
    return 0;
  }

  error_code = EVP_PKEY_assign_EC_KEY(pkey, ec_key);
  if (error_code == 0) {
    fprintf(stderr, "Error assigning EC_KEY key to EVP_PKEY structure.\n");
    EVP_PKEY_free(pkey);
    EC_KEY_free(ec_key);
    return 0;
  }

  /*
   * Extract EC-specific key from the EVP_PKEY structure. EVP_PKEY_get1_EC_KEY()
   * increments the reference count, so we must call EC_KEY_free() later to avoid
   * memory leaks. Returns NULL if pkey does not contain an EC key.
   *
   * The returned EC_KEY must be freed with EC_KEY_free() when no longer needed.
   * EC_KEY_free() decrements the reference count and frees the memory if the
   * count reaches zero.
   */
  ec_key = EVP_PKEY_get1_EC_KEY(pkey);
  if (ec_key == NULL) {
    fprintf(stderr, "Error: getting referenced EVP_PKEY. ");
    fprintf(stderr, "EVP_PKEY key structure is not of the correct type.\n");
    EVP_PKEY_free(pkey);
    return 0;
  }

  /* Write private and public keys' (binary data) in PEM format. */
  error_code = WriteKeysToPEMFiles(pkey, pubkey_file, privkey_file);
  if (error_code == 0) {
    fprintf(stderr, "Writing private and public keys in PEM format files failed.\n");
    EVP_PKEY_free(pkey);
    EC_KEY_free(ec_key);
    return 0;
  }

  /* Free memory. */
  EVP_PKEY_free(pkey);
  EC_KEY_free(ec_key);

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

  /* Create the Input/Output BIO's. */
  BIO* out_bio  = BIO_new(BIO_s_file());
  if (out_bio == NULL) {
    fprintf(stderr, "Creating a new OpenSSL BIO failed.\n");
    return 0;
  }

  /* Prepare file and BIO for writing private key data in PEM format. */
  out_bio = BIO_new_file(privkey_file, "w");
  if (out_bio == NULL) {
    fprintf(stderr, "Unable to create a new PEM file BIO with writing mode.\n");
    BIO_free_all(out_bio);
    return 0;
  }

  /* Write private key data in PEM format. */
  int error_code = PEM_write_bio_PrivateKey(out_bio, pkey, NULL, NULL, 0, 0, NULL);
  if (error_code == 0) {
    fprintf(stderr, "Error writing private key data in PEM format.\n");
    BIO_free_all(out_bio);
    return 0;
  }

  /* Prepare file and BIO for writing public key data in PEM format. */
  out_bio = BIO_new_file(pubkey_file, "w");
  if (out_bio == NULL) {
    fprintf(stderr, "Unable to create a new PEM file BIO with writing mode.\n");
    BIO_free_all(out_bio);
    return 0;
  }

  /*  Write public key data in PEM format. */
  error_code = PEM_write_bio_PUBKEY(out_bio, pkey);
  if (error_code == 0) {
    fprintf(stderr, "Error writing public key data in PEM format.\n");
    BIO_free_all(out_bio);
    return 0;
  }

  /* Free memory. */
  BIO_free_all(out_bio);

  return 1;
}

