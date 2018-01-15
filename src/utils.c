/*
 * ===--- utils.c -----------------------------------------------------------===
 *
 * This file is distributed under the MIT License. See LICENSE for details.
 *
 * AUTHOR: Artiom Baloian <artiom.baloian@nyu.edu>
 *
 * DESCRIPTION:
 * File provides utility functionalities for eccpem lib.
 */

#include "utils.h"

#include <stdio.h>
#include <string.h>

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
int VerifyPemFileFormat(const char* pem_file) {

  if (pem_file == NULL) {
    fprintf(stderr, "Error: Provided public/private key file cannot be NULL "
                    "it must be PEM format.\n");
    return 0;
  }

  /* Key files must be in PEM format with .pem extension. */
  const char* pem_file_last_dot = strrchr(pem_file, '.');
  if (pem_file_last_dot == NULL) {
    fprintf(stderr, "Error: Provided public/private key file must be PEM "
                    "format (extension is .pem).\n");
    return 0;
  } else {
    if (strcmp(pem_file_last_dot, ".pem") != 0) {
      fprintf(stderr, "Error: Provided public/private key file must be PEM "
                      "format (extension is .pem).\n");
      return 0;
    }
  }

  return 1;
}

