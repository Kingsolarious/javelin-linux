/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * javelin-status — live event monitor
 *
 * connects to the eBPF loader UNIX socket and prints security
 * events in real time. useful for debugging and demos.
 *
 * build: gcc -O2 -Wall src/javelin-status.c -o build/javelin-status
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>

#define SOCKET_PATH "/run/javelin/ebpf.sock"

static volatile int g_running = 1;

static void sigint_handler(int sig)
{
    (void)sig;
    g_running = 0;
}

struct jv_event {
    uint32_t type;
    uint32_t pid;
    uint64_t timestamp_ns;
    uint64_t addr;
    uint32_t flags;
    uint32_t reserved;
};

static const char *event_name(uint32_t type);

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    int fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", SOCKET_PATH);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "javelin-status: cant connect to %s: %s\n", SOCKET_PATH, strerror(errno));
        fprintf(stderr, "is the loader running? try: sudo ./build/javelin-loader ...\n");
        close(fd);
        return 1;
    }

    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    printf("javelin-status: connected. waiting for events...\n");
    printf("(press Ctrl-C to exit)\n\n");

    while (g_running) {
        struct jv_event ev;
        ssize_t n = recv(fd, &ev, sizeof(ev), 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("recv");
            break;
        }
        if (n == 0) {
            printf("javelin-status: loader disconnected\n");
            break;
        }
        if (n != (ssize_t)sizeof(ev)) {
            printf("javelin-status: short read (%zd bytes)\n", n);
            continue;
        }

        double ms = (double)ev.timestamp_ns / 1000000.0;
        printf("[%10.3f ms] %-15s pid=%u addr=0x%llx flags=%u\n",
               ms, event_name(ev.type), ev.pid,
               (unsigned long long)ev.addr, ev.flags);
        fflush(stdout);
    }

    close(fd);
    return 0;
}

static const char *event_name(uint32_t type)
{
    switch (type) {
    case 1: return "MPROTECT_EXEC";
    case 2: return "PTRACE_ATTACH";
    case 3: return "MODULE_LOAD";
    case 4: return "KALLSYMS_ACCESS";
    case 5: return "TIMER_ANOMALY";
    default: return "UNKNOWN";
    }
}
