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

#ifndef ECCPEM_READ_H_
#define ECCPEM_READ_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <openssl/ec.h>

/*
 * Function reads private key's pem file and stores it in a given array as a
 * binary data.
 *
 * Arguments:
 * - privkey_file: PEM formatted file (extension is .pem) from where it is going
 *                 to be read private key and store in a array as a binary data.
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
                          const unsigned int key_size);



#ifdef __cplusplus
}
#endif

#endif

