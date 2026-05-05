/*
 * javelin linux native implementation
 *
 * core engine. speaks linux natively:
 * - /proc for process introspection
 * - process_vm_readv/writev for memory access
 * - mmap/mprotect for memory management
 * - pthreads for threading
 * - ptrace for debug operations
 *
 * no windows types, no wine glue. pure linux code that implements the
 * contract javelin's windows DLL expects.
 */

#include "javelin.h"
#include "../platform/linux/attestation.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <sys/sysinfo.h>
#include <pthread.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <signal.h>

static int prot_from_jv(uint32_t p)
{
    int r = PROT_NONE;
    if (p & JV_PROT_READ)  r |= PROT_READ;
    if (p & JV_PROT_WRITE) r |= PROT_WRITE;
    if (p & JV_PROT_EXEC)  r |= PROT_EXEC;
    return r;
}

static pid_t handle_to_pid(jv_handle_t h)
{
    if (h == JV_INVALID_HANDLE || h == NULL)
        return getpid();
    return (pid_t)(uintptr_t)h;
}

struct sys_basic_info {
    uint32_t page_size;
    uint32_t phys_pages;
    uint32_t alloc_gran;
    uint64_t min_user_addr;
    uint64_t max_user_addr;
    char     num_cpus;
};

jv_result_t jv_query_system_info(int info_class, void *buf, uint32_t len, uint32_t *out_len)
{
    if (!buf && len != 0)
        return JV_ERR_INVALID;

    switch (info_class) {
    case JV_SYS_BASIC: {
        struct sys_basic_info info = {0};
        struct sysinfo si;
        if (sysinfo(&si) != 0)
            return JV_ERR_DENIED;

        info.page_size   = (uint32_t)sysconf(_SC_PAGESIZE);
        info.phys_pages  = (uint32_t)sysconf(_SC_PHYS_PAGES);
        info.alloc_gran  = info.page_size;
        info.min_user_addr = 0x0000000000010000ULL;
        info.max_user_addr = 0x00007FFFFFFFFFFFULL;
        info.num_cpus    = (char)sysconf(_SC_NPROCESSORS_ONLN);

        size_t copy = (len < sizeof(info)) ? len : sizeof(info);
        memcpy(buf, &info, copy);
        if (out_len) *out_len = (uint32_t)sizeof(info);
        return JV_OK;
    }
    default:
        if (buf) memset(buf, 0, len);
        if (out_len) *out_len = len;
        return JV_OK;
    }
}

jv_result_t jv_query_process_info(jv_handle_t proc, int info_class, void *buf, uint32_t len, uint32_t *out_len)
{
    pid_t pid = handle_to_pid(proc);

    switch (info_class) {
    case JV_PROC_BASIC: {
        struct { int32_t exit; void *peb; uint64_t aff; int32_t prio; uint64_t pid; uint64_t parent; } info = {0};
        info.pid = (uint64_t)pid;
        info.prio = 8;
        size_t copy = (len < sizeof(info)) ? len : sizeof(info);
        memcpy(buf, &info, copy);
        if (out_len) *out_len = (uint32_t)sizeof(info);
        return JV_OK;
    }
    case JV_PROC_DEBUG_PORT: {
        uint32_t port = 0;
        size_t copy = (len < sizeof(port)) ? len : sizeof(port);
        memcpy(buf, &port, copy);
        if (out_len) *out_len = (uint32_t)sizeof(port);
        return JV_OK;
    }
    case JV_PROC_IMAGE_NAME: {
        char path[512];
        char link[64];
        snprintf(link, sizeof(link), "/proc/%d/exe", pid);
        ssize_t rc = readlink(link, path, sizeof(path) - 1);
        if (rc < 0) return JV_ERR_DENIED;
        path[rc] = '\0';
        size_t copy = (len < (size_t)rc + 1) ? len : (size_t)rc + 1;
        memcpy(buf, path, copy);
        if (out_len) *out_len = (uint32_t)(rc + 1);
        return JV_OK;
    }
    default:
        if (buf) memset(buf, 0, len);
        if (out_len) *out_len = len;
        return JV_OK;
    }
}

jv_result_t jv_open_process(jv_handle_t *out, uint32_t access, void *client_id)
{
    (void)access;
    if (!out || !client_id)
        return JV_ERR_INVALID;

    pid_t pid = *(pid_t *)client_id;
    if (pid <= 0 || (kill(pid, 0) != 0 && errno != EPERM))
        return JV_ERR_DENIED;

    *out = (jv_handle_t)(uintptr_t)pid;
    return JV_OK;
}

jv_result_t jv_close_handle(jv_handle_t h)
{
    (void)h;
    return JV_OK;
}

jv_result_t jv_read_memory(jv_handle_t proc, void *addr, void *buf, uint32_t len, uint32_t *out_len)
{
    pid_t pid = handle_to_pid(proc);
    struct iovec local  = { .iov_base = buf, .iov_len = len };
    struct iovec remote = { .iov_base = addr, .iov_len = len };
    ssize_t rc = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    if (rc < 0) {
        if (out_len) *out_len = 0;
        return JV_ERR_DENIED;
    }
    if (out_len) *out_len = (uint32_t)rc;
    return JV_OK;
}

jv_result_t jv_write_memory(jv_handle_t proc, void *addr, const void *buf, uint32_t len, uint32_t *out_len)
{
    pid_t pid = handle_to_pid(proc);
    struct iovec local  = { .iov_base = (void *)buf, .iov_len = len };
    struct iovec remote = { .iov_base = addr, .iov_len = len };
    ssize_t rc = process_vm_writev(pid, &local, 1, &remote, 1, 0);
    if (rc < 0) {
        if (out_len) *out_len = 0;
        return JV_ERR_DENIED;
    }
    if (out_len) *out_len = (uint32_t)rc;
    return JV_OK;
}

jv_result_t jv_protect_memory(jv_handle_t proc, void **addr, uint32_t *len, uint32_t prot, uint32_t *old_prot)
{
    (void)proc;
    long ps = sysconf(_SC_PAGESIZE);
    void *page = (void *)(((uintptr_t)*addr) & ~(ps - 1));
    size_t plen = *len;
    if (page != *addr)
        plen += (size_t)((uintptr_t)*addr - (uintptr_t)page);

    if (mprotect(page, plen, prot_from_jv(prot)) != 0)
        return JV_ERR_DENIED;

    if (old_prot) *old_prot = 0;
    return JV_OK;
}

jv_result_t jv_alloc_memory(jv_handle_t proc, void **addr, uint32_t *len, uint32_t flags, uint32_t prot)
{
    (void)proc;
    if (!addr || !len)
        return JV_ERR_INVALID;

    int mflags = MAP_PRIVATE | MAP_ANONYMOUS;
    void *want = *addr;
    if (want != NULL && (flags & JV_MEM_TOPDOWN)) {
#ifdef MAP_FIXED_NOREPLACE
        mflags |= MAP_FIXED_NOREPLACE;
#else
        mflags |= MAP_FIXED;
#endif
    }

    void *mem = mmap(want, *len, prot_from_jv(prot), mflags, -1, 0);
    if (mem == MAP_FAILED)
        return JV_ERR_DENIED;

    *addr = mem;
    return JV_OK;
}

jv_result_t jv_free_memory(jv_handle_t proc, void **addr, uint32_t *len, uint32_t free_type)
{
    (void)proc;
    (void)free_type;
    if (!addr || !len)
        return JV_ERR_INVALID;
    if (munmap(*addr, *len) != 0)
        return JV_ERR_DENIED;
    *addr = NULL;
    *len = 0;
    return JV_OK;
}

jv_result_t jv_flush_icache(jv_handle_t proc, void *addr, uint32_t len)
{
    (void)proc;
    if (addr && len > 0)
        __builtin___clear_cache((char *)addr, (char *)addr + len);
    return JV_OK;
}

jv_result_t jv_create_thread(jv_handle_t *out, void *start, void *arg)
{
    pthread_t tid;
    int rc = pthread_create(&tid, NULL, (void *(*)(void *))start, arg);
    if (rc != 0)
        return JV_ERR_DENIED;
    *out = (jv_handle_t)(uintptr_t)tid;
    return JV_OK;
}

jv_result_t jv_debug_attach(jv_handle_t proc)
{
    pid_t pid = handle_to_pid(proc);
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0)
        return JV_ERR_DENIED;
    waitpid(pid, NULL, 0);
    return JV_OK;
}

jv_result_t jv_debug_detach(jv_handle_t proc)
{
    pid_t pid = handle_to_pid(proc);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return JV_OK;
}

jv_result_t jv_query_value(void *key, void *name, uint32_t class, void *buf, uint32_t len, uint32_t *out_len)
{
    (void)key; (void)name; (void)class;
    if (!buf && len != 0)
        return JV_ERR_INVALID;
    if (buf) memset(buf, 0, len);
    if (out_len) *out_len = 0;
    return JV_OK;
}

jv_result_t jv_create_file(jv_handle_t *out, const char *path, uint32_t access, uint32_t disposition)
{
    (void)path; (void)access; (void)disposition;
    int fd = open("/dev/null", O_RDONLY);
    if (fd < 0)
        return JV_ERR_DENIED;
    *out = (jv_handle_t)(uintptr_t)(unsigned int)fd;
    return JV_OK;
}

jv_result_t jv_register_callbacks(void *reg, void **out)
{
    (void)reg;
    static int dummy = 1;
    *out = &dummy;
    return JV_OK;
}

void jv_unregister_callbacks(void *cb)
{
    (void)cb;
}

int jv_init(void)
{
    if (prctl(PR_SET_DUMPABLE, 0) < 0)
        return -1;
    jv_attestation_start();
    return 0;
}

void jv_fini(void)
{
    jv_attestation_stop();
}
