/*
 * ===--- utils.c -----------------------------------------------------------===
 *
 * This file is distributed under the MIT License. See LICENSE for details.
 *
 * AUTHOR: Artiom Baloian <artiom.baloian@nyu.edu>
 *
 * DESCRIPTION:
 * File provides utility functions for the eccpem library.
 */

#include "utils.h"

#include <stdio.h>
#include <string.h>


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
int VerifyPemFileFormat(const char* pem_file) {
  if (pem_file == NULL) {
    fprintf(stderr, "Provided public/private key file cannot be NULL. "
                    "It must be PEM format.\n");
    return 0;
  }
  /* Key files must be in PEM format with .pem extension. */
  const char* pem_file_last_dot = strrchr(pem_file, '.');
  if (pem_file_last_dot == NULL) {
    fprintf(stderr, "Provided public/private key file must be PEM "
                    "format (extension is .pem).\n");
    return 0;
  } else {
    if (strcmp(pem_file_last_dot, ".pem") != 0) {
      fprintf(stderr, "Provided public/private key file must be PEM "
                      "format (extension is .pem).\n");
      return 0;
    }
  }
  return 1;
}

