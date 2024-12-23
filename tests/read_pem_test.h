#include "unit_tests_api.h"
#include "eccpem_read.h"
#include "eccpem_write.h"
#include <stdio.h>
#include <unistd.h>

#define GREEN "\x1B[1;32m"
#define RESET "\x1B[0m"

void RUN_READ_PRIVATE_KEY_TESTS() {
  printf("\nTesting ReadPrivateKeyPemFile...\n");

  // First create test key files
  const char* pub_file = "test_pubkey.pem";
  const char* priv_file = "test_privkey.pem";
  CreateECCKeysPemFiles("prime256v1", pub_file, priv_file);

  // Test valid private key reading
  uint8_t private_key[32]; // prime256v1 uses 32 bytes
  int ret_value = ReadPrivateKeyPemFile(priv_file, private_key, 32);
  TEST_ASSERT_EQUAL_INT(ret_value, 1);
  printf("✓ Valid private key read successfully\n");

  // Test NULL private key array
  printf("\nExpected error message:\nPrivate key's array cannot be null.\n");
  printf("Actual output:\n");
  ret_value = ReadPrivateKeyPemFile(priv_file, NULL, 32);
  TEST_ASSERT_EQUAL_INT(ret_value, 0);
  printf("✓ NULL private key array rejected\n");

  // Test zero key size
  printf("\nExpected error message:\nPrivate key's array size cannot be null. Check it using openssl ecparam -list_curves command.\n");
  printf("Actual output:\n");
  ret_value = ReadPrivateKeyPemFile(priv_file, private_key, 0);
  TEST_ASSERT_EQUAL_INT(ret_value, 0);
  printf("✓ Zero key size rejected\n");

  // Test non-existent file
  printf("\nExpected error message:\nUnable to open private key's pem file or it does not exist.\n");
  printf("Actual output:\n");
  ret_value = ReadPrivateKeyPemFile("nonexistent.pem", private_key, 32);
  TEST_ASSERT_EQUAL_INT(ret_value, 0);
  printf("✓ Non-existent file rejected\n");

  // Test invalid file extension
  const char* invalid_file = "test_key.txt";
  printf("\nExpected error message:\nProvided public/private key file must be PEM format (extension is .pem).\n");
  printf("Actual output:\n");
  ret_value = ReadPrivateKeyPemFile(invalid_file, private_key, 32);
  TEST_ASSERT_EQUAL_INT(ret_value, 0);
  printf("✓ Invalid file extension rejected\n");

  // Cleanup
  remove(pub_file);
  remove(priv_file);

  printf("\nTesting ReadPrivateKeyPemFile ------------------------------------- [ " GREEN "PASSED" RESET " ]\n");
}
