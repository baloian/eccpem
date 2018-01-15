/*
 * ===--- utils.h -----------------------------------------------------------===
 *
 * This file is distributed under the MIT License. See LICENSE for details.
 *
 * AUTHOR: Artiom Baloian <artiom.baloian@nyu.edu>
 *
 * DESCRIPTION:
 * File provides utility functionalities for eccpem lib.
 */

#ifndef ECCPEM_UTILS_H_
#define ECCPEM_UTILS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>



/*
 * Function verifies input files format. They have to be PEM formatted and
 * extension is .pem
 *
 * Arguments:
 * - pem_file: Public key PEM formatted file path.
 *
 * Returns:
 * - 1 if files verification was successful.
 * - 0 if files verification failed.
 */
int VerifyPemFileFormat(const char* pem_file);



#ifdef __cplusplus
}
#endif

#endif

