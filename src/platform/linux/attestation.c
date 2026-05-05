/*
 * linux platform attestation service.
 * connects to eBPF agent via UNIX socket and reports events.
 * runs as a background thread in the shim.
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <pthread.h>

#define REPORT_INTERVAL_MS 5000
#define MAX_REPORT_SIZE    4096
#define EBPF_SOCKET_PATH   "/run/javelin/ebpf.sock"

struct jv_event {
    uint32_t type;
    uint32_t pid;
    uint64_t timestamp_ns;
    uint64_t addr;
    uint32_t flags;
    uint32_t reserved;
};

static int ebpf_fd = -1;
static volatile bool running = false;
static pthread_t report_thread;

static int connect_ebpf(void)
{
    int fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (fd < 0) return -1;

    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, EBPF_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void format_report(char *buf, size_t max, const struct jv_event *ev)
{
    const char *t = "UNKNOWN";
    switch (ev->type) {
    case 1: t = "MPROTECT_EXEC"; break;
    case 2: t = "PTRACE_ATTACH"; break;
    case 3: t = "MODULE_LOAD"; break;
    case 4: t = "KALLSYMS_ACCESS"; break;
    case 5: t = "TIMER_ANOMALY"; break;
    }
    snprintf(buf, max,
        "{\"t\":\"%s\",\"pid\":%u,\"ts\":%llu,\"addr\":\"0x%llx\",\"flags\":%u}",
        t, ev->pid, (unsigned long long)ev->timestamp_ns,
        (unsigned long long)ev->addr, ev->flags);
}

static void *report_loop(void *arg)
{
    (void)arg;
    char report[MAX_REPORT_SIZE];

    while (running) {
        struct timespec ts = {
            .tv_sec = REPORT_INTERVAL_MS / 1000,
            .tv_nsec = (REPORT_INTERVAL_MS % 1000) * 1000000L
        };
        nanosleep(&ts, NULL);

        if (ebpf_fd >= 0) {
            struct jv_event ev;
            ssize_t rc = recv(ebpf_fd, &ev, sizeof(ev), MSG_DONTWAIT);
            if (rc == (ssize_t)sizeof(ev)) {
                format_report(report, sizeof(report), &ev);
                fprintf(stderr, "[javelin-attest] %s\n", report);
            }
        }
    }
    return NULL;
}

void jv_attestation_start(void)
{
    fprintf(stderr, "[javelin] Attestation start\n");
    mkdir("/run/javelin", 0755);

    ebpf_fd = connect_ebpf();
    if (ebpf_fd < 0)
        fprintf(stderr, "[javelin] eBPF agent unavailable (%s)\n", strerror(errno));

    running = true;
    pthread_create(&report_thread, NULL, report_loop, NULL);
}

void jv_attestation_stop(void)
{
    running = false;
    pthread_join(report_thread, NULL);
    if (ebpf_fd >= 0) {
        close(ebpf_fd);
        ebpf_fd = -1;
    }
}
