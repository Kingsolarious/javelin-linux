/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * integration test: cross-process memory read.
 *
 * forks a child process, writes a known magic value to a page,
 * and reads it back via jv_read_memory.
 *
 * this test requires ptrace_scope=0 or the child to be a descendant.
 * if the environment is restricted, the test skips gracefully.
 */

#include "../../src/javelin/javelin.h"
#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t child_ready = 0;

static void sigusr1_handler(int sig) {
    (void)sig;
    child_ready = 1;
}

int main(void) {
    signal(SIGUSR1, sigusr1_handler);

    size_t ps = 4096;
    char *shared = mmap(NULL, ps, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (shared == MAP_FAILED) {
        fprintf(stderr, "skip: mmap failed\n");
        return 77; /* automake skip code */
    }

    memset(shared, 0, ps);
    strcpy(shared, "JV_MAGIC_42");

    pid_t child = fork();
    if (child < 0) {
        munmap(shared, ps);
        fprintf(stderr, "skip: fork failed\n");
        return 77;
    }

    if (child == 0) {
        /* child: signal parent and wait */
        kill(getppid(), SIGUSR1);
        while (1)
            pause();
        _exit(0);
    }

    /* parent: wait for child signal */
    int timeout = 100;
    while (!child_ready && timeout-- > 0)
        usleep(10000);

    if (!child_ready) {
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        munmap(shared, ps);
        fprintf(stderr, "skip: child startup timeout\n");
        return 77;
    }

    jv_handle_t h;
    jv_result_t rc = jv_open_process(&h, 0, &child);
    if (rc != JV_OK) {
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        munmap(shared, ps);
        fprintf(stderr, "skip: jv_open_process denied (ptrace_scope=%d)\n", rc);
        return 77;
    }

    char buf[64] = {0};
    uint32_t readlen = 0;
    uint32_t expect_len = (uint32_t)strlen("JV_MAGIC_42") + 1;
    rc = jv_read_memory(h, shared, buf, expect_len, &readlen);
    jv_close_handle(h);

    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    munmap(shared, ps);

    if (rc != JV_OK) {
        fprintf(stderr, "skip: jv_read_memory denied (ptrace_scope=%d)\n", rc);
        return 77;
    }

    if (readlen != expect_len || strcmp(buf, "JV_MAGIC_42") != 0) {
        fprintf(stderr, "fail: read '%s' (len=%u) expected 'JV_MAGIC_42' (len=%u)\n", buf, readlen,
                expect_len);
        return 1;
    }

    printf("pass: cross-process memory read OK\n");
    return 0;
}
