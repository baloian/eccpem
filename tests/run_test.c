#include "test_utils.h"
#include "create_keys_test.h"
#include "read_pem_test.h"
int main() {

  RUN_UTILS_TESTS();
  RUN_CREATE_KEYS_TESTS();
  RUN_READ_PRIVATE_KEY_TESTS();

  return 0;
}

