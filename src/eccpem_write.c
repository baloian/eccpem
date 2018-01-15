/*
 * ===--- eccpem_write.c ----------------------------------------------------===
 *
 * This file is distributed under the MIT License. See LICENSE for details.
 *
 * AUTHOR: Artiom Baloian <artiom.baloian@nyu.edu>
 *
 * DESCRIPTION:
 * File provides Elliptic Curve Cryptography key pairs generator, write keys
 * to PEM formatted files and file format verification functions'
 * implementation.
 */

#include "eccpem_write.h"
#include "utils.h"

#include <stdio.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

/*
 * Function generates Elliptic Curve Cryptography - ECC key pairs and writes to
 * PEM formatted files for private and public keys separately.
 * Function rewrites provided file if it exists or creates a new file if it does
 * not exist.
 *
 * Arguments:
 * - ec_type: Elliptic Curve type. To list the supported curves run:
 *            $ openssl ecparam -list_curves
 * - pubkey_file: PEM formatted file (extension is .pem) where is going to be
 *                stored public key.
 * - privkey_file: PEM formatted file (extension is .pem) where is going to be
 *                 stored private key.
 *
 * Returns:
 * - 1 if generation of key pairs was successful.
 * - 0 if Creating a new OpenSSL EC_KEY object failed,
 *     generates a new EC public and private key failed,
 *     generating the newly allocated EVP_PKEY failed,
 *     error assigning EC_KEY key to EVP_PKEY structure or
 *     writing private and public keys in PEM format files failed.
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
   * Extract EC-specifics from the key, it returns the referenced key in pkey
   * or NULL if the key is not of the correct type.
   * We should do it because EC_KEY_free() decrements the reference count for
   * the EC_KEY object, and if it has dropped to zero then frees the memory
   * associated with it.
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
 * Function writes private and public keys, represented by EVP_PKEY structure,
 * in given files. It rewrites provided file if it exists or creates a new file
 * if it does not exist.
 *
 * Arguments:
 * - pkey: EVP_PKEY structure, which represents private and public keys.
 * - pubkey_file: Public key file, it must be PEM format.
 * - privkey_file: Private key file, it must be PEM format.
 *
 * Return:
 * - 1 if PEM files are created successfully.
 * - 0 if creating PEM files failed.
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

