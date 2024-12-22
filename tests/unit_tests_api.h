/*
 * ===--- unit_tests_api.h --------------------------------------------------===
 *
 * This file is distributed under the MIT License. See LICENSE for details.
 *
 * AUTHOR: Artiom Baloian <artiom.baloian@nyu.edu>
 *
 * DESCRIPTION:
 * File provides API for unit tests.
 */


#ifndef ECCPEM_UNIT_TESTS_API_H_
#define ECCPEM_UNIT_TESTS_API_H_

#include <string.h>
#include <assert.h>
#include <stdio.h>

/*
 * Compare two null-terminated strings. It fails if one of arguments is NULL or
 * any character is different or if the lengths are different.
 */
void TEST_ASSERT_EQUAL_STRING(const char *expected, const char *actual) {
  if (expected == NULL) {
    fprintf(stderr, "TEST_ASSERT_EQUAL_STRING failed: expected string is NULL\n");
    assert(0);
  }
  if (actual == NULL) {
    fprintf(stderr, "TEST_ASSERT_EQUAL_STRING failed: actual string is NULL\n");
    assert(0);
  }

  const int ret_value = strcmp(expected, actual);
  if (ret_value != 0) {
    fprintf(stderr, "TEST_ASSERT_EQUAL_STRING failed:\n");
    fprintf(stderr, "Expected: \"%s\"\n", expected);
    fprintf(stderr, "Actual  : \"%s\"\n", actual);
    assert(0);
  }
}

/*
 * Compare two null-terminated strings. It fails if one of arguments is NULL or
 * provided expected and actual strings are the same (they contain exactly the
 * same characters).
 */
void TEST_ASSERT_NOT_EQUAL_STRING(const char *expected, const char *actual) {
  if (expected == NULL) {
    fprintf(stderr, "TEST_ASSERT_NOT_EQUAL_STRING failed: expected string is NULL\n");
    assert(0);
  }
  if (actual == NULL) {
    fprintf(stderr, "TEST_ASSERT_NOT_EQUAL_STRING failed: actual string is NULL\n");
    assert(0);
  }

  const int ret_value = strcmp(expected, actual);
  if (ret_value == 0) {
    fprintf(stderr, "TEST_ASSERT_NOT_EQUAL_STRING failed:\n");
    fprintf(stderr, "Expected strings to be different but both are: \"%s\"\n", expected);
    assert(0);
  }
}

/*
 * Compare two integers for equality. A cast will be performed to your natural
 * integer size. Fails if expected integer value is not equal to actual integer
 * value.
 */
void TEST_ASSERT_EQUAL_INT(const int expected, const int actual) {
  if (expected != actual) {
    fprintf(stderr, "TEST_ASSERT_EQUAL_INT failed:\n");
    fprintf(stderr, "Expected: %d\n", expected);
    fprintf(stderr, "Actual  : %d\n", actual);
    assert(0);
  }
}

#endif
