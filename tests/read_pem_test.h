#include <stdio.h>
#include <unistd.h>

#include "eccpem_read.h"
#include "eccpem_write.h"
#include "unit_tests_api.h"

#define GREEN "\x1B[1;32m"
#define RESET "\x1B[0m"

void RUN_READ_PRIVATE_KEY_TESTS() {
  printf("\nTesting ReadPrivateKeyPemFile...\n");

  // First create test key files
  const char* pub_file = "test_pubkey.pem";
  const char* priv_file = "test_privkey.pem";
  CreateECCKeysPemFiles("prime256v1", pub_file, priv_file);

  // Test valid private key reading
  uint8_t private_key[32];  // prime256v1 uses 32 bytes
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
  printf(
      "\nExpected error message:\nPrivate key's array size cannot be null. "
      "Check it using openssl ecparam -list_curves command.\n");
  printf("Actual output:\n");
  ret_value = ReadPrivateKeyPemFile(priv_file, private_key, 0);
  TEST_ASSERT_EQUAL_INT(ret_value, 0);
  printf("✓ Zero key size rejected\n");

  // Test non-existent file
  printf(
      "\nExpected error message:\nUnable to open private key's pem file or it "
      "does not exist.\n");
  printf("Actual output:\n");
  ret_value = ReadPrivateKeyPemFile("nonexistent.pem", private_key, 32);
  TEST_ASSERT_EQUAL_INT(ret_value, 0);
  printf("✓ Non-existent file rejected\n");

  // Test invalid file extension
  const char* invalid_file = "test_key.txt";
  printf(
      "\nExpected error message:\nProvided public/private key file must be PEM "
      "format (extension is .pem).\n");
  printf("Actual output:\n");
  ret_value = ReadPrivateKeyPemFile(invalid_file, private_key, 32);
  TEST_ASSERT_EQUAL_INT(ret_value, 0);
  printf("✓ Invalid file extension rejected\n");

  // Cleanup
  remove(pub_file);
  remove(priv_file);

  printf(
      "\nTesting ReadPrivateKeyPemFile ------------------------------------- "
      "[ " GREEN "PASSED" RESET " ]\n");
}

void RUN_READ_PUBLIC_KEY_TESTS() {
  printf("\nTesting ReadPublicKeyPemFile...\n");

  // First create test key files
  const char* pub_file = "test_pubkey.pem";
  const char* priv_file = "test_privkey.pem";
  CreateECCKeysPemFiles("prime256v1", pub_file, priv_file);

  // Test valid public key reading
  uint8_t public_key[33];  // Compressed public key is 33 bytes
  int ret_value = ReadPublicKeyPemFile(pub_file, public_key, 33);
  TEST_ASSERT_EQUAL_INT(ret_value, 1);
  printf("✓ Valid public key read successfully\n");

  // Test NULL public key array
  printf(
      "\nExpected error message:\nPublic key output buffer cannot be NULL\n");
  printf("Actual output:\n");
  ret_value = ReadPublicKeyPemFile(pub_file, NULL, 33);
  TEST_ASSERT_EQUAL_INT(ret_value, 0);
  printf("✓ NULL public key array rejected\n");

  // Test zero key size
  printf(
      "\nExpected error message:\nInvalid compressed key size. Expected 33 "
      "bytes for ECDSA compressed public key\n");
  printf("Actual output:\n");
  ret_value = ReadPublicKeyPemFile(pub_file, public_key, 0);
  TEST_ASSERT_EQUAL_INT(ret_value, 0);
  printf("✓ Zero key size rejected\n");

  // Test non-existent file
  printf("\nExpected error message:\nFailed to open public key PEM file\n");
  printf("Actual output:\n");
  ret_value = ReadPublicKeyPemFile("nonexistent.pem", public_key, 33);
  TEST_ASSERT_EQUAL_INT(ret_value, 0);
  printf("✓ Non-existent file rejected\n");

  // Test invalid file extension
  const char* invalid_file = "test_key.txt";
  printf(
      "\nExpected error message:\nProvided public/private key file must be PEM "
      "format (extension is .pem).\n");
  printf("Actual output:\n");
  ret_value = ReadPublicKeyPemFile(invalid_file, public_key, 33);
  TEST_ASSERT_EQUAL_INT(ret_value, 0);
  printf("✓ Invalid file extension rejected\n");

  // Cleanup
  remove(pub_file);
  remove(priv_file);

  printf(
      "\nTesting ReadPublicKeyPemFile -------------------------------------- "
      "[ " GREEN "PASSED" RESET " ]\n");
}
