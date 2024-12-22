#include "unit_tests_api.h"
#include "eccpem_write.h"
#include <stdio.h>
#include <unistd.h>

#define GREEN "\x1B[1;32m"
#define RESET "\x1B[0m"

void RUN_CREATE_KEYS_TESTS() {
  printf("\nTesting CreateECCKeysPemFiles...\n");

  // Test valid key creation
  const char* pub_file = "test_pubkey.pem";
  const char* priv_file = "test_privkey.pem";
  int ret_value = CreateECCKeysPemFiles("prime256v1", pub_file, priv_file);
  TEST_ASSERT_EQUAL_INT(ret_value, 1);
  
  // Verify files were created
  if(access(pub_file, F_OK) == 0 && access(priv_file, F_OK) == 0) {
    printf("✓ Key files created successfully\n");
    remove(pub_file);
    remove(priv_file);
  }

  // Test NULL curve type
  printf("\nExpected error message:\n"
         "Elliptic Curve type cannot be NULL. Run 'openssl ecparam -list_curves' command to list EC types.\n");
  printf("Actual output:\n");
  ret_value = CreateECCKeysPemFiles(NULL, pub_file, priv_file);
  TEST_ASSERT_EQUAL_INT(ret_value, 0);
  printf("\n✓ NULL curve type rejected\n");

  // Test invalid curve name
  ret_value = CreateECCKeysPemFiles("invalid_curve", pub_file, priv_file);
  TEST_ASSERT_EQUAL_INT(ret_value, 0);
  printf("✓ Invalid curve name rejected\n");

  // Test invalid file extensions
  const char* invalid_pub = "test_pubkey.txt";
  const char* invalid_priv = "test_privkey.txt";
  printf("\nExpected error message:\n"
         "Provided public/private key file must be PEM format (extension is .pem).\n");
  printf("Actual output:\n");
  ret_value = CreateECCKeysPemFiles("prime256v1", invalid_pub, invalid_priv);
  TEST_ASSERT_EQUAL_INT(ret_value, 0);
  printf("✓ Invalid file extensions rejected\n");

  printf("\nTesting CreateECCKeysPemFiles ------------------------------------- [ " GREEN "PASSED" RESET " ]\n");
}
