/*
 * ===--- utils.h -----------------------------------------------------------===
 *
 * This file is distributed under the MIT License. See LICENSE for details.
 *
 * AUTHOR: Artiom Baloian <artiom.baloian@nyu.edu>
 *
 * DESCRIPTION:
 * File provides utility functions for the eccpem library.
 */

#ifndef ECCPEM_UTILS_H_
#define ECCPEM_UTILS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>


/*
 * Function verifies that the input file has a .pem extension and is properly
 * formatted as a PEM file.
 *
 * Arguments:
 * - pem_file: Path to the file to verify. The file should be a PEM-formatted
 *            file with a .pem extension.
 *
 * Returns:
 * - 1 if the file exists, has a .pem extension, and is properly PEM-formatted.
 * - 0 if the file does not exist, lacks a .pem extension, or is not properly
 *     PEM-formatted.
 */
int VerifyPemFileFormat(const char* pem_file);


#ifdef __cplusplus
}
#endif

#endif

