#include "unit_tests_api.h"
#include "utils.h"
#include <stdio.h>

#define GREEN "\x1B[1;32m"
#define RESET "\x1B[0m"

void RUN_UTILS_TESTS() {

  const char* pem_file = "test_pemfile.pem";
  int ret_value = VerifyPemFileFormat(pem_file);
  TEST_ASSERT_EQUAL_INT(ret_value, 1);


  const char* not_pem_file = "test_pemfile.not_pem";

  printf("\nExpected output: \n"
         "Error: Provided public/private key file must be PEM format (extension is .pem).\n");
  printf("Real output: \n");

  ret_value = VerifyPemFileFormat(not_pem_file);
  TEST_ASSERT_EQUAL_INT(ret_value, 0);



  printf("\nExpected output: \n"
         "Error: Provided public/private key file cannot be NULL it must be PEM format.\n");

  printf("Real output: \n");
  ret_value = VerifyPemFileFormat(NULL);
  TEST_ASSERT_EQUAL_INT(ret_value, 0);


  printf("\nTesting VerifyPemFileFormat ----------------------------------------- [ "
         GREEN "PASSED" RESET " ]\n");
}

