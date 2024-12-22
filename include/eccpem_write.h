/*
 * ===--- eccpem_write.h ----------------------------------------------------===
 *
 * This file is distributed under the MIT License. See LICENSE for details.
 *
 * AUTHOR: Artiom Baloian <artiom.baloian@nyu.edu>
 *
 * DESCRIPTION:
 * File provides functionality to generate Elliptic Curve Cryptography (ECC) key pairs
 * and write them to PEM formatted files.
 */

#ifndef ECCPEM_WRITE_H_
#define ECCPEM_WRITE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/ec.h>

/*
 * Function generates Elliptic Curve Cryptography (ECC) key pairs and writes them to
 * PEM formatted files. If the specified files already exist, they will be overwritten.
 * Otherwise, new files will be created.
 *
 * Arguments:
 * - ec_type: Elliptic Curve type. To list the supported curves run:
 *            $ openssl ecparam -list_curves
 * - pubkey_file: PEM formatted file (extension is .pem) where the public key will
 *                be stored.
 * - privkey_file: PEM formatted file (extension is .pem) where the private key will
 *                 be stored.
 *
 * Returns:
 * - 1 if generation of key pairs and writing them to PEM files was successful.
 * - 0 if any of the following operations fail:
 *     - Creating a new OpenSSL EC_KEY object
 *     - Generating EC public and private keys
 *     - Allocating and assigning keys to EVP_PKEY structure
 *     - Writing keys to PEM format files
 */
int CreateECCKeysPemFiles(const char* ec_type,
                          const char* pubkey_file,
                          const char* privkey_file);



/*
 * Function writes ECC key pairs from an EVP_PKEY structure to PEM formatted files.
 * If the specified files already exist, they will be overwritten. Otherwise, new
 * files will be created.
 *
 * Arguments:
 * - pkey: EVP_PKEY structure containing the ECC public and private key pair
 * - pubkey_file: PEM formatted file (extension is .pem) where the public key will
 *                be stored
 * - privkey_file: PEM formatted file (extension is .pem) where the private key will
 *                 be stored
 *
 * Returns:
 * - 1 if writing both keys to PEM files was successful
 * - 0 if writing either key to its PEM file failed
 */
static int WriteKeysToPEMFiles(EVP_PKEY* pkey,
                               const char* pubkey_file,
                               const char* privkey_file);



#ifdef __cplusplus
}
#endif

#endif

