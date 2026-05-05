/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * linux platform attestation service.
 *
 * background thread that pulls events from the eBPF agent,
 * checks system security state, and reports telemetry.
 *
 * nick wrote this. it leaks memory if you restart the loader
 * because we never implemented socket reconnection. dyllan
 * keeps saying hell fix it and never does.
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
#include <sys/mman.h>
#include <sys/uio.h>
#include <pthread.h>

#define REPORT_INTERVAL_MS 5000
#define MAX_REPORT_SIZE    4096
#define EBPF_SOCKET_PATH   "/run/javelin/ebpf.sock"

/* must match eBPF struct exactly. changing this breaks the ABI
 * between loader and shim. dont do it. */
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
    /* use snprintf instead of strncpy because strncpy is broken.
     * it doesnt null-terminate if the source is longer than the dest,
     * and sun_path is only 108 bytes. some distros use long paths
     * for abstract sockets. */
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", EBPF_SOCKET_PATH);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* read a single integer from /proc or sysfs. returns -1 on error.
 * kernel exports these as ascii. no, i dont know why either. */
static int read_int_file(const char *path)
{
    char buf[32];
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = '\0';
    /* atoi ignores trailing garbage, which is fine for /proc values
     * that end with newline. strtol would be cleaner but atoi works. */
    return atoi(buf);
}

/* yama ptrace_scope. 0 = no restrictions, 3 = full lockdown.
 * ubuntu defaults to 1 since 10.10. fedora defaults to 0.
 * steamos 3.5 uses 1. */
static int get_ptrace_scope(void)
{
    return read_int_file("/proc/sys/kernel/yama/ptrace_scope");
}

/* check secure boot status via efivars. fallback to lockdown mode.
 * efivar path is stable since linux 3.8. before that, good luck. */
static bool secure_boot_enabled(void)
{
    uint8_t buf[8];
    int fd = open("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c", O_RDONLY);
    if (fd >= 0) {
        /* first 4 bytes are attributes (u32), next is the value (u8).
         * EFI spec is weird. */
        if (read(fd, buf, 5) == 5) {
            close(fd);
            return buf[4] == 1;
        }
        close(fd);
    }
    /* fallback: lockdown mode implies secure boot or someone ran
     * `lockdown=1` on the kernel cmdline. close enough. */
    int lockdown = read_int_file("/sys/kernel/security/lockdown");
    return lockdown > 0;
}

/* djb2 hash of a memory region. not cryptographic. real anti-cheats
 * use SHA256 or better but this is just for a quick integrity check
 * on W->X transitions. if you want real security, use a real hash. */
static uint64_t hash_memory_region(pid_t pid, void *addr, size_t len)
{
    /* FIXME: no upper bound on len. if someone passes 4GB we OOM.
     * caller currently only passes 4KB so its fine. */
    struct iovec local  = { .iov_base = malloc(len), .iov_len = len };
    struct iovec remote = { .iov_base = addr, .iov_len = len };
    if (!local.iov_base)
        return 0;

    ssize_t rc = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    if (rc < 0) {
        free(local.iov_base);
        return 0;
    }

    uint64_t hash = 5381;
    unsigned char *p = local.iov_base;
    for (ssize_t i = 0; i < rc; i++)
        hash = ((hash << 5) + hash) + p[i];

    free(local.iov_base);
    return hash;
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

    uint64_t memhash = 0;
    if (ev->type == 1 && ev->addr != 0) {
        /* hash first 4KB. this is what real anti-cheats do
         * to detect unauthorized code modifications. */
        memhash = hash_memory_region((pid_t)ev->pid, (void *)ev->addr, 4096);
    }

    /* yes, this is hand-rolled json. no, i dont want to link jansson
     * or cJSON for 6 fields. sue me. */
    snprintf(buf, max,
        "{\"t\":\"%s\",\"pid\":%u,\"ts\":%llu,\"addr\":\"0x%llx\",\"flags\":%u,\"hash\":\"0x%llx\"}",
        t, ev->pid, (unsigned long long)ev->timestamp_ns,
        (unsigned long long)ev->addr, ev->flags,
        (unsigned long long)memhash);
}

static void print_system_state(void)
{
    int ptrace_scope = get_ptrace_scope();
    bool sb = secure_boot_enabled();
    fprintf(stderr, "[javelin-attest] system state: ptrace_scope=%d secure_boot=%s\n",
            ptrace_scope, sb ? "yes" : "no");
}

/* nanosleep can be interrupted by signals. we dont restart it because
 * the signal is probably SIGTERM telling us to die anyway. */
static void *report_loop(void *arg)
{
    (void)arg;
    char report[MAX_REPORT_SIZE];
    int state_report_counter = 0;

    while (running) {
        struct timespec ts = {
            .tv_sec = REPORT_INTERVAL_MS / 1000,
            .tv_nsec = (REPORT_INTERVAL_MS % 1000) * 1000000L
        };
        nanosleep(&ts, NULL);

        if (++state_report_counter >= 6) {
            state_report_counter = 0;
            print_system_state();
        }

        /* drain events from eBPF. MSG_DONTWAIT means we dont block.
         * we only drain one event per wakeup. if the ringbuf is
         * flooding well lag behind. real code would loop until
         * EAGAIN but this is a PoC. */
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

/* FIXME: race condition. if jv_attestation_stop() is called before
 * the thread starts, pthread_join on an uninitialized pthread_t is
 * UB. this cant happen in normal use because init/fini are called
 * from library constructor/destructor, but its still wrong. */
void jv_attestation_start(void)
{
    fprintf(stderr, "[javelin] attestation start\n");
    mkdir("/run/javelin", 0755);

    print_system_state();

    ebpf_fd = connect_ebpf();
    if (ebpf_fd < 0)
        fprintf(stderr, "[javelin] eBPF agent unavailable: %s\n", strerror(errno));

    running = true;
    if (pthread_create(&report_thread, NULL, report_loop, NULL) != 0) {
        fprintf(stderr, "[javelin] failed to start attestation thread\n");
        running = false;
    }
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
