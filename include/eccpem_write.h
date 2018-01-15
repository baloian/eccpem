/*
 * ===--- eccpem_write.h ----------------------------------------------------===
 *
 * This file is distributed under the MIT License. See LICENSE for details.
 *
 * AUTHOR: Artiom Baloian <artiom.baloian@nyu.edu>
 *
 * DESCRIPTION:
 * File provides Elliptic Curve Cryptography key pairs generator and write keys
 * to PEM formatted files.
 */

#ifndef ECCPEM_WRITE_H_
#define ECCPEM_WRITE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/ec.h>

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
                          const char* privkey_file);



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
                               const char* privkey_file);



#ifdef __cplusplus
}
#endif

#endif

