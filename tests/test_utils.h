#include "unit_tests_api.h"
#include "utils.h"
#include <stdio.h>

#define GREEN "\x1B[1;32m"
#define RESET "\x1B[0m"

void RUN_UTILS_TESTS() {

  const char* pem_file = "test_pemfile.pem";
  int ret_value = VerifyPemFileFormat(pem_file);
  TEST_ASSERT_EQUAL_INT(ret_value, 1);

  printf("Testing VerifyPemFileFormat ----------------------------------------- [ "
         GREEN "PASSED" RESET " ]\n");

  //TEST_ASSERT_EQUAL_STRING(expected, actual);
}

