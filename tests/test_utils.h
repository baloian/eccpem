#include "unit_tests_api.h"
#include "utils.h"
#include <stdio.h>

#define GREEN "\x1B[1;32m"
#define RESET "\x1B[0m"

void RUN_UTILS_TESTS() {
  printf("\nTesting VerifyPemFileFormat...\n");

  // Test valid PEM file
  const char* pem_file = "test_pemfile.pem";
  int ret_value = VerifyPemFileFormat(pem_file);
  TEST_ASSERT_EQUAL_INT(ret_value, 1);
  printf("✓ Valid PEM file accepted\n");

  // Test invalid extension
  const char* not_pem_file = "test_pemfile.not_pem";
  printf("\nExpected error message:\n"
         "Provided public/private key file must be PEM format (extension is .pem).\n");
  printf("Actual output:\n");
  ret_value = VerifyPemFileFormat(not_pem_file);
  TEST_ASSERT_EQUAL_INT(ret_value, 0);
  printf("✓ Invalid extension rejected\n");

  // Test NULL input
  printf("\nExpected error message:\n"
         "Provided public/private key file must be PEM format (extension is .pem).\n");
  printf("Actual output:\n");
  ret_value = VerifyPemFileFormat(NULL);
  TEST_ASSERT_EQUAL_INT(ret_value, 0);
  printf("✓ NULL input rejected\n");

  // Test empty string
  printf("\nExpected error message:\n"
         "Provided public/private key file must be PEM format (extension is .pem).\n");
  printf("Actual output:\n");
  ret_value = VerifyPemFileFormat("");
  TEST_ASSERT_EQUAL_INT(ret_value, 0);
  printf("✓ Empty string rejected\n");

  // Test file with multiple extensions
  const char* multi_ext = "test.txt.pem";
  ret_value = VerifyPemFileFormat(multi_ext);
  TEST_ASSERT_EQUAL_INT(ret_value, 1);
  printf("✓ Multiple extensions handled correctly\n");

  printf("\nTesting VerifyPemFileFormat ----------------------------------------- [ "
         GREEN "PASSED" RESET " ]\n");
}
