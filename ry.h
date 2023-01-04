/*
    MIT License
    Copyright (c) 2023 Adi Salimgereyev (Vertex)
    Permission is hereby granted, free of charge, to any person obtaining a
    copy of this software and associated dorymentation files (the "Software"),
   to deal in the Software without restriction, including without limitation the
    rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
    sell copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:
    The above copyright notice and this permission notice shall be included
    in all copies or substantial portions of the Software.
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
    OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTIryLAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
    THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
    IN THE SOFTWARE.
 */

#ifndef _RY_H_
#define _RY_H_

#include <unistd.h>

#ifdef RY_ENABLE_TIMER
#include <time.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifdef __cplusplus
#define RY_TEST(name) extern "C" void name(void)
#else /* __cplusplus */
#define RY_TEST(name) void name(void)
#endif /* __cplusplus */

#define RY_TEST_SUITE(name) ry_test_suite_t test_suite_##name[] =

#define TEST_SUITE_CLOSURE                                                     \
  { NULL, NULL }

#define TEST_SUITES ry_test_suites_t ry_test_suites[] =
#define TEST_SUITES_CLOSURE                                                    \
  { NULL, NULL }
#define TEST_SUITE_ADD(name)                                                   \
  { #name, test_suite_##name }

#define TEST_ADD(name)                                                         \
  { #name, name }

#define RY_RUN(argc, argv) ry_run(argc, argv)

#define RY_SET_OUT_PREFIX(str) ry_set_out_prefix(str)

#define RY_SET_OUT_PER_TEST(yes) ry_set_out_per_test(yes)

#define assert_trueq(a, msg)                                                   \
  if (a) {                                                                     \
    ry_success_assertion();                                                    \
  } else {                                                                     \
    ry_fail_assertion(__FILE__, __LINE__, msg);                                \
  }
#define assert_true(a) assert_trueq((a), #a " is not true")

#define assert_falseq(a, msg) assert_trueq(!(a), msg)
#define assert_false(a) assertFalseM((a), #a " is not false")

#define assert_equalsq(a, b, msg) assert_trueq((a) == (b), msg)
#define assert_equals(a, b) assert_equalsq((a), (b), #a " != " #b)

#define assert_not_equalsq(a, b, msg) assert_trueq((a) != (b), msg)
#define assert_not_equals(a, b) assert_not_equalsq((a), (b), #a " == " #b)

#define RY_NAME_BUFFER_SIZE 20

typedef void (*ry_testing_func_t)(void);

typedef struct _ry_test_suite_t {
  const char *name;
  ry_testing_func_t func;
} ry_test_suite_t;

typedef struct _ry_test_suites_t {
  const char *name;
  ry_test_suite_t *test_suite;
} ry_test_suites_t;

extern ry_test_suites_t ry_test_suites[];
int ry_run(int argc, char *argv[]);
void ry_success_assertion(void);
void ry_fail_assertion(const char *file, int line, const char *msg);
void ry_set_out_prefix(const char *str);
void ry_set_out_per_test(int yes);

/** Timer **/
#ifdef RY_ENABLE_TIMER

const struct timespec *ry_timer(void);
void ry_start_timer(void);
const struct timespec *ry_stop_timer(void);

#endif /* RY_ENABLE_TIMER */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif