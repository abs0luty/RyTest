/*
    MIT License
    Copyright (c) 2023 Adi Salimgereyev (Vertex)
    Permission is hereby granted, free of charge, to any person obtaining a
    copy of this software and associated documentation files (the "Software"),
   to deal in the Software without restriction, including without limitation the
    rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
    sell copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:
    The above copyright notice and this permission notice shall be included
    in all copies or substantial portions of the Software.
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
    OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
    THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
    IN THE SOFTWARE.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>

#include "ry.h"

char *strsignal(int sig);

static size_t ry_success_checks_amount = 0;
static size_t ry_fail_checks_amount = 0;

static const char *ry_current_test_name;

static size_t ry_success_tests_amount = 0;
static size_t ry_fail_tests_amount = 0;

static const char *ry_current_test_suite_name;

static size_t ry_success_test_suites_amount = 0;
static size_t ry_fail_test_suites_amount = 0;

static int fd;

static bool test_failed;

#define RY_OUT_PREFIX_BUFFER_SIZE 128
static char ry_out_prefix[RY_OUT_PREFIX_BUFFER_SIZE + 1] = "";
static bool ry_out_per_test = false;

#define CHECK_FAILED_MESSAGE_CODE '0'
#define CHECK_SUCCEED_MESSAGE_CODE '1'
#define TEST_FAILED_MESSAGE_CODE '2'
#define TEST_SUCCEED_MESSAGE_CODE '3'
#define TEST_SUITE_FAILED_MESSAGE_CODE '4'
#define TEST_SUITE_SUCCEED_MESSAGE_CODE '5'
#define ENDED_MESSAGE_CODE '6'
#define TEST_NAME_MESSAGE_CODE '7'

#define MSG_CHECK_SUCCEED write(fd, "1\n", 2)
#define MSG_TEST_FAILED write(fd, "2\n", 2)
#define MSG_TEST_SUCCEED write(fd, "3\n", 2)
#define MSG_TEST_SUITE_FAILED write(fd, "4\n", 2)
#define MSG_TEST_SUITE_SUCCEED write(fd, "5\n", 2)
#define MSG_END write(fd, "6\n", 2)

#define BUF_LEN 1000
#define MSGBUF_LEN 300

static void redirect_out_err(const char *testName);

static void close_out_err(void);

static void redirect_test_out_err(const char *test_suite, const char *test);

static int run_test(const char *t_name, ry_testing_func_t t_func);

static void run_test_suite(const char *ts_name, ry_test_suite_t *ts,
                           int test_id);

static void receive_messages(void);

static int ry_run_test_suite(const char *test_suite_name,
                             const char *test_name);

static void ry_run_fork(const char *ts_name, ry_test_suite_t *test_suite,
                        int test_id);

static void ry_print_results(void);

static float time_diff_seconds(const struct timespec *start,
                               const struct timespec *end);

int ry_run(int argc, char *argv[]) {
  ry_test_suites_t *tss;

  char *test_suite_name, *test_name;

  bool found = 0;

  if (argc > 1) {
    for (int i = 1; i < argc; i++) {
      test_suite_name = argv[i];
      test_name = test_suite_name;
      for (; *test_name && *test_name != ':'; ++test_name)
        ;
      if (*test_name != 0x0) {
        *test_name = 0x0;
        ++test_name;
      } else {
        test_name = NULL;
      }

      found |= ry_run_test_suite(test_suite_name, test_name);
    }

    if (found == 1)
      ry_print_results();

  } else {
    tss = ry_test_suites;
    while (tss->name != NULL && tss->test_suite != NULL) {
      ry_run_fork(tss->name, tss->test_suite, -1);
      tss++;
    }
    ry_print_results();
  }

  if (ry_fail_test_suites_amount > 0)
    return -1;
  return 0;
}

static int ry_run_test_suite(const char *test_suite_name,
                             const char *test_name) {
  ry_test_suites_t *tss;
  ry_test_suite_t *ts;
  int found = 0;
  register int i;

  tss = ry_test_suites;
  while (tss->name != NULL && tss->test_suite != NULL) {
    if (strcmp(test_suite_name, tss->name) == 0) {
      if (test_name != NULL) {
        for (i = 0, ts = tss->test_suite; ts->name != NULL && ts->func != NULL;
             ++i, ++ts) {
          if (strcmp(ts->name, test_name) == 0) {
            break;
          }
        }

        if (ts->name != NULL && ts->func != NULL) {
          found = 1;
          ry_run_fork(tss->name, tss->test_suite, i);
        }
      } else {
        found = 1;
        ry_run_fork(tss->name, tss->test_suite, -1);
      }
      break;
    }
    tss++;
  }

  if (!found) {
    if (test_name != NULL) {
      fprintf(stderr, "ERROR: Could not find test suite '%s:%s'\n",
              test_suite_name, test_name);
    } else {
      fprintf(stderr, "ERROR: Could not find test suite '%s'\n",
              test_suite_name);
    }
  }

  return found;
}

static void ry_run_fork(const char *ts_name, ry_test_suite_t *ts, int test_id) {
  struct timespec time_start, time_end;
  int pipefd[2];
  int pid;
  int status;

  if (pipe(pipefd) == -1) {
    perror("Pipe error");
    exit(-1);
  }

  clock_gettime(CLOCK_MONOTONIC, &time_start);
  fprintf(stdout, " -> %s [IN PROGESS]\n", ts_name);
  fflush(stdout);

  pid = fork();
  if (pid < 0) {
    perror("Fork error");
    exit(-1);
  }

  if (pid == 0) {
    close(pipefd[0]);

    fd = pipefd[1];

    run_test_suite(ts_name, ts, test_id);

    MSG_END;
    close(fd);

    exit(0);
  } else {
    close(pipefd[1]);

    fd = pipefd[0];

    receive_messages();

    wait(&status);
    if (!WIFEXITED(status)) {
      if (WIFSIGNALED(status)) {
        fprintf(stdout, "Test suite was terminated by signal %d (%s).\n",
                WTERMSIG(status), strsignal(WTERMSIG(status)));
      } else {
        fprintf(stdout, "Test suite terminated abnormaly!\n");
      }

      ry_fail_test_suites_amount++;
    } else {
      int exit_status = WEXITSTATUS(status);
      if (exit_status != 0) {
        fprintf(stdout, "Test suite terminated with exit status %d.\n",
                exit_status);
        ry_fail_test_suites_amount++;
      }
    }

    close(fd);

    clock_gettime(CLOCK_MONOTONIC, &time_end);
    fprintf(stdout, " -> %s [DONE %.2fs]\n\n", ts_name,
            time_diff_seconds(&time_start, &time_end));
    fflush(stdout);
  }
}

static int run_test(const char *t_name, ry_testing_func_t t_func) {
  struct timespec time_start, time_end;
  int test_suite_failed = 0;
  char buffer[MSGBUF_LEN];
  int len;

  if (ry_out_per_test)
    redirect_test_out_err(ry_current_test_suite_name, t_name);

  test_failed = false;

  ry_current_test_name = t_name;

  len = snprintf(buffer, MSGBUF_LEN, "%c    --> %s ...\n",
                 TEST_NAME_MESSAGE_CODE, ry_current_test_name);
  write(fd, buffer, len);
  fsync(fd);

  clock_gettime(CLOCK_MONOTONIC, &time_start);
  (*(t_func))();
  clock_gettime(CLOCK_MONOTONIC, &time_end);
  len = snprintf(buffer, MSGBUF_LEN, "%c    --> %s [DONE %.4fs]\n",
                 TEST_NAME_MESSAGE_CODE, ry_current_test_name,
                 time_diff_seconds(&time_start, &time_end));
  write(fd, buffer, len);

  if (test_failed) {
    MSG_TEST_FAILED;
    test_suite_failed = 1;
  } else {
    MSG_TEST_SUCCEED;
  }

  return test_suite_failed;
}

static void run_test_suite(const char *ts_name, ry_test_suite_t *ts,
                           int test_id) {
  int test_suite_failed = 0;

  ry_current_test_suite_name = ts_name;

  if (!ry_out_per_test)
    redirect_out_err(ry_current_test_suite_name);

  while (test_id == -1 && ts->name != NULL && ts->func != NULL) {
    test_suite_failed |= run_test(ts->name, ts->func);
    ts++;
  }

  if (test_id != -1) {
    ts += test_id;
    test_suite_failed |= run_test(ts->name, ts->func);
  }

  if (test_suite_failed) {
    MSG_TEST_SUITE_FAILED;
  } else {
    MSG_TEST_SUITE_SUCCEED;
  }

  close_out_err();
}

static void receive_messages(void) {
  char buf[BUF_LEN];
  int buf_len;
  char bufout[MSGBUF_LEN];
  int bufout_len;
  int state = 0;
  int end = 0;

  bufout_len = 0;
  while ((buf_len = read(fd, buf, BUF_LEN)) > 0 && !end) {
    for (int i = 0; i < buf_len; i++) {
      if (buf[i] == '\n') {
        if (state == 1) {
          write(1, bufout, bufout_len);
          write(1, "\n", 1);
        }
        if (state == 2) {
          write(2, bufout, bufout_len);
          write(2, "\n", 1);
        }

        state = 0;
        bufout_len = 0;

      } else if (state == 1 || state == 2) {
        if (bufout_len < MSGBUF_LEN)
          bufout[bufout_len++] = buf[i];

      } else if (state == 0) {
        if (buf[i] == CHECK_FAILED_MESSAGE_CODE) {
          ry_fail_checks_amount++;
          state = 2;
        } else if (buf[i] == TEST_NAME_MESSAGE_CODE) {
          state = 1;
        } else if (buf[i] == CHECK_SUCCEED_MESSAGE_CODE) {
          ry_success_checks_amount++;
        } else if (buf[i] == TEST_FAILED_MESSAGE_CODE) {
          ry_fail_tests_amount++;
        } else if (buf[i] == TEST_SUCCEED_MESSAGE_CODE) {
          ry_success_tests_amount++;
        } else if (buf[i] == TEST_SUITE_FAILED_MESSAGE_CODE) {
          ry_fail_test_suites_amount++;
        } else if (buf[i] == TEST_SUITE_SUCCEED_MESSAGE_CODE) {
          ry_success_test_suites_amount++;
        } else if (buf[i] == ENDED_MESSAGE_CODE) {
          end = 1;
          break;
        }
      }
    }
  }
}

void ry_success_assertion(void) { MSG_CHECK_SUCCEED; }

void ry_fail_assertion(const char *file, int line, const char *msg) {
  char buf[MSGBUF_LEN];
  int len;

  len = snprintf(buf, MSGBUF_LEN, "%c%s:%d (%s::%s) :: %s\n",
                 CHECK_FAILED_MESSAGE_CODE, file, line,
                 ry_current_test_suite_name, ry_current_test_name, msg);
  write(fd, buf, len);

  test_failed = true;
}

static void ry_print_results(void) {
  fprintf(stdout, "\n");
  fprintf(stdout, "==================================================\n");
  fprintf(stdout, "|               |  failed  |  succeed  |  total  |\n");
  fprintf(stdout, "|------------------------------------------------|\n");
  fprintf(stdout, "| assertions:   |  %6d  |  %7d  |  %5d  |\n",
          ry_fail_checks_amount, ry_success_checks_amount,
          ry_success_checks_amount + ry_fail_checks_amount);
  fprintf(stdout, "| tests:        |  %6d  |  %7d  |  %5d  |\n",
          ry_fail_tests_amount, ry_success_tests_amount,
          ry_success_tests_amount + ry_fail_tests_amount);
  fprintf(stdout, "| tests suites: |  %6d  |  %7d  |  %5d  |\n",
          ry_fail_test_suites_amount, ry_success_test_suites_amount,
          ry_success_test_suites_amount + ry_fail_test_suites_amount);
  fprintf(stdout, "==================================================\n");
}

void ry_set_out_prefix(const char *str) {
  strncpy(ry_out_prefix, str, RY_OUT_PREFIX_BUFFER_SIZE);
}

void ry_set_out_per_test(int yes) { ry_out_per_test = yes; }

static void redirect_out_err(const char *test_name) {
  redirect_test_out_err(test_name, NULL);
}

static void redirect_test_out_err(const char *test_suite, const char *test) {
  char buf[256];

  if (test != NULL) {
    snprintf(buf, 255, "%stmp.%s.%s.out", ry_out_prefix, test_suite, test);
  } else {
    snprintf(buf, 255, "%stmp.%s.out", ry_out_prefix, test_suite);
  }

  fprintf(stdout, buf);

  if (test != NULL) {
    snprintf(buf, 255, "%stmp.%s.%s.err", ry_out_prefix, test_suite, test);
  } else {
    snprintf(buf, 255, "%stmp.%s.err", ry_out_prefix, test_suite);
  }

  fprintf(stderr, buf);
}

static void close_out_err(void) {
  fclose(stdout);
  fclose(stderr);
}

#ifdef RY_ENABLE_TIMER
/* global variables for timer functions */
static struct timespec __ry_timer;
static struct timespec __ry_timer_start, __ry_timer_stop;

const struct timespec *ry_timer(void) { return &__ry_timer; }

void ry_start_timer(void) { clock_gettime(CLOCK_MONOTONIC, &__ry_timer_start); }

const struct timespec *ry_stop_timer(void) {
  clock_gettime(CLOCK_MONOTONIC, &__ry_timer_stop);

  /* store into t difference between time_start and time_end */
  if (__ry_timer_stop.tv_nsec > __ry_timer_start.tv_nsec) {
    __ry_timer.tv_nsec = __ry_timer_stop.tv_nsec - __ry_timer_start.tv_nsec;
    __ry_timer.tv_sec = __ry_timer_stop.tv_sec - __ry_timer_start.tv_sec;
  } else {
    __ry_timer.tv_nsec =
        __ry_timer_stop.tv_nsec + 1000000000L - __ry_timer_start.tv_nsec;
    __ry_timer.tv_sec = __ry_timer_stop.tv_sec - 1 - __ry_timer_start.tv_sec;
  }

  return &__ry_timer;
}

#endif /* RY_ENABLE_TIMER */

static float time_diff_seconds(const struct timespec *start,
                               const struct timespec *end) {
  struct timespec diff;
  float sec;

  if (end->tv_nsec > start->tv_nsec) {
    diff.tv_nsec = end->tv_nsec - start->tv_nsec;
    diff.tv_sec = end->tv_sec - start->tv_sec;
  } else {
    diff.tv_nsec = end->tv_nsec + 1000000000L - start->tv_nsec;
    diff.tv_sec = end->tv_sec - 1 - start->tv_sec;
  }

  sec = diff.tv_nsec / 1000000000.f;
  sec += diff.tv_sec;
  return sec;
}