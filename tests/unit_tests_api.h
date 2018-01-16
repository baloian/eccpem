/*
 * ===--- unit_tests_api.h --------------------------------------------------===
 *
 * This file is distributed under the MIT License. See LICENSE for details.
 *
 * AUTHOR: Artiom Baloian <artiom.baloian@nyu.edu>
 *
 * DESCRIPTION:
 * File provides API for uni tests.
 */


#ifndef ECCPEM_UNIT_TESTS_API_H_
#define ECCPEM_UNIT_TESTS_API_H_

#include <string.h>
#include <assert.h>


/*
 * Compare two null-terminated strings. It fails if one of arguments is NULL or
 * any character is different or if the lengths are different.
 */
void TEST_ASSERT_EQUAL_STRING(const char *expected, const char *actual) {

  assert(expected != NULL);
  assert(actual != NULL);

  const int ret_value = strcmp(expected, actual);

  assert(ret_value == 0);
}



/*
 * Compare two null-terminated strings. It fails if one of arguments is NULL or
 * provided expected and actual strings are the same (they contain exactly the
 * same characters).
 */
void TEST_ASSERT_NOT_EQUAL_STRING(const char *expected, const char *actual) {
  
  assert(expected != NULL);
  assert(actual != NULL);

  const int ret_value = strcmp(expected, actual);

  assert(ret_value != 0);
}



/*
 * Compare two integers for equality. A cast will be performed to your natural
 * integer size. Failes if expected integer value is not equal to actual integer
 * value.
 */
void TEST_ASSERT_EQUAL_INT(const int expected, const int actual) {
  assert(expected == actual);
}

#endif

