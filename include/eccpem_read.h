/*
 * ===--- eccpem_read.h -----------------------------------------------------===
 *
 * This file is distributed under the MIT License. See LICENSE for details.
 *
 * AUTHOR: Artiom Baloian <artiom.baloian@nyu.edu>
 *
 * DESCRIPTION:
 * File provides functionality to read Elliptic Curve Cryptography (ECC) key pairs
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
                          const unsigned int key_size);



/*
 * Function reads public key's PEM file and stores it in a given array as binary data.
 * Note that the array will contain a compressed public key.
 *
 * Arguments:
 * - pubkey_file: PEM formatted file (extension is .pem) from which the public key
 *                will be read and stored in an array as binary data.
 * - public_key: An array where the compressed public key will be stored.
 * - compressed_key_size: Size of array. Basically compressed public key size is 33 byte.
 *
 * Returns:
 * - 1 if reading PEM file and storing data to array was successful.
 * - 0 if it cannot open the provided PEM file, cannot read the provided PEM file,
 *     fails to convert EVP_PKEY to EC_KEY, or fails to read compressed EC public key.
 */
int ReadPublicKeyPemFile(const char* pubkey_file,
                         uint8_t public_key[],
                         const unsigned int compressed_key_size);



#ifdef __cplusplus
}
#endif

#endif

