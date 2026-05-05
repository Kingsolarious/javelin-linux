/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * javelin linux native implementation
 *
 * core engine. implements what the windows javelin DLL expects
 * using linux syscalls.
 */

#include "javelin.h"
#include "../platform/linux/arch.h"
#include "../platform/linux/attestation.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

/* windows PAGE_EXECUTE_READWRITE flags -> linux prot bits */
static int prot_from_jv(uint32_t p) {
    int r = PROT_NONE;
    if (p & JV_PROT_READ)
        r |= PROT_READ;
    if (p & JV_PROT_WRITE)
        r |= PROT_WRITE;
    if (p & JV_PROT_EXEC)
        r |= PROT_EXEC;
    return r;
}

static uint32_t prot_to_jv(int p) {
    uint32_t r = JV_PROT_NONE;
    if (p & PROT_READ)
        r |= JV_PROT_READ;
    if (p & PROT_WRITE)
        r |= JV_PROT_WRITE;
    if (p & PROT_EXEC)
        r |= JV_PROT_EXEC;
    return r;
}

/* ==========================================================================
 * handle table
 *
 * windows uses opaque handles. the shim tracks threads and files so
 * jv_close_handle actually releases resources. process handles remain
 * as raw pid casts for compatibility with existing callers.
 * ========================================================================== */

enum hnd_type {
    HND_NONE = 0,
    HND_PROCESS,
    HND_THREAD,
    HND_FILE,
};

struct hnd_entry {
    enum hnd_type type;
    union {
        pid_t pid;
        pthread_t thread;
        int fd;
    } u;
};

#define MAX_HANDLES 64

static struct hnd_entry handle_table[MAX_HANDLES];
static pthread_mutex_t handle_mutex = PTHREAD_MUTEX_INITIALIZER;

static jv_handle_t alloc_handle(enum hnd_type type) {
    pthread_mutex_lock(&handle_mutex);
    for (int i = 0; i < MAX_HANDLES; i++) {
        if (handle_table[i].type == HND_NONE) {
            handle_table[i].type = type;
            pthread_mutex_unlock(&handle_mutex);
            /* offset by 1 so NULL is never a valid handle index */
            return (jv_handle_t)(uintptr_t)(i + 1);
        }
    }
    pthread_mutex_unlock(&handle_mutex);
    return JV_INVALID_HANDLE;
}

static struct hnd_entry *resolve_handle(jv_handle_t h) {
    uintptr_t idx = (uintptr_t)h;
    if (idx == 0 || idx > (uintptr_t)MAX_HANDLES)
        return NULL;
    return &handle_table[idx - 1];
}

static void free_handle_entry(struct hnd_entry *e) {
    if (!e)
        return;
    if (e->type == HND_THREAD)
        pthread_detach(e->u.thread);
    else if (e->type == HND_FILE)
        close(e->u.fd);
    e->type = HND_NONE;
}

/* NULL handle means "current process". windows uses GetCurrentProcess()
 * which is ((HANDLE)-1). same approach here. */
static pid_t handle_to_pid(jv_handle_t h) {
    if (h == JV_INVALID_HANDLE || h == NULL)
        return getpid();
    struct hnd_entry *e = resolve_handle(h);
    if (e && e->type == HND_PROCESS)
        return e->u.pid;
    /* legacy: untracked handle treated as raw pid */
    return (pid_t)(uintptr_t)h;
}

/* ==========================================================================
 * yama / capability helpers
 * ========================================================================== */

static int read_int_file(const char *path) {
    char buf[32];
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0)
        return -1;
    buf[n] = '\0';
    return atoi(buf);
}

static int get_ptrace_scope(void) {
    return read_int_file("/proc/sys/kernel/yama/ptrace_scope");
}

static bool has_cap_sys_ptrace(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f)
        return false;
    char line[256];
    bool has = false;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "CapEff:", 7) == 0) {
            unsigned long long cap = strtoull(line + 7, NULL, 16);
            /* CAP_SYS_PTRACE = 19 */
            has = (cap & (1ULL << 19)) != 0;
            break;
        }
    }
    fclose(f);
    return has;
}

static bool is_descendant(pid_t ancestor, pid_t child) {
    pid_t current = child;
    while (current > 1) {
        char path[64];
        snprintf(path, sizeof(path), "/proc/%d/status", current);
        FILE *f = fopen(path, "r");
        if (!f)
            return false;
        char line[256];
        pid_t ppid = -1;
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "PPid:", 5) == 0) {
                ppid = atoi(line + 6);
                break;
            }
        }
        fclose(f);
        if (ppid == ancestor)
            return true;
        if (ppid <= 1)
            return false;
        current = ppid;
    }
    return false;
}

/* ==========================================================================
 * /proc/PID/maps parser
 * ========================================================================== */

static int parse_maps_protection(const char *line, void *addr, uint32_t *out_prot) {
    char *endptr;
    unsigned long long start = strtoull(line, &endptr, 16);
    if (*endptr != '-')
        return -1;
    unsigned long long end = strtoull(endptr + 1, &endptr, 16);
    uintptr_t a = (uintptr_t)addr;
    if (a < start || a >= end)
        return -1;
    /* skip space, then read rwx */
    while (*endptr == ' ')
        endptr++;
    int prot = PROT_NONE;
    if (endptr[0] == 'r')
        prot |= PROT_READ;
    if (endptr[1] == 'w')
        prot |= PROT_WRITE;
    if (endptr[2] == 'x')
        prot |= PROT_EXEC;
    *out_prot = prot_to_jv(prot);
    return 0;
}

static int get_page_protection(pid_t pid, void *addr, uint32_t *out_prot) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (parse_maps_protection(line, addr, out_prot) == 0) {
            fclose(f);
            return 0;
        }
    }
    fclose(f);
    return -1;
}

/* ==========================================================================
 * NtQuerySystemInformation
 * ========================================================================== */

struct sys_basic_info {
    uint32_t page_size;
    uint32_t phys_pages;
    uint32_t alloc_gran;
    uint64_t min_user_addr;
    uint64_t max_user_addr;
    char num_cpus;
};

jv_result_t jv_query_system_info(int info_class, void *buf, uint32_t len, uint32_t *out_len) {
    if (!buf && len != 0)
        return JV_ERR_INVALID;

    switch (info_class) {
    case JV_SYS_BASIC: {
        struct sys_basic_info info = {0};
        struct sysinfo si;
        if (sysinfo(&si) != 0)
            return JV_ERR_DENIED;

        info.page_size = (uint32_t)sysconf(_SC_PAGESIZE);
        info.phys_pages = (uint32_t)sysconf(_SC_PHYS_PAGES);
        info.alloc_gran = info.page_size;
        info.min_user_addr = JV_ARCH_MIN_ADDR;
        info.max_user_addr = JV_ARCH_MAX_ADDR;
        info.num_cpus = (char)sysconf(_SC_NPROCESSORS_ONLN);

        size_t copy = (len < sizeof(info)) ? len : sizeof(info);
        memcpy(buf, &info, copy);
        if (out_len)
            *out_len = (uint32_t)sizeof(info);
        return JV_OK;
    }
    default:
        /* unknown info class. zero the buffer to prevent undefined behavior. */
        if (buf)
            memset(buf, 0, len);
        if (out_len)
            *out_len = len;
        return JV_OK;
    }
}

/* ==========================================================================
 * NtQueryInformationProcess
 * ========================================================================== */

jv_result_t jv_query_process_info(jv_handle_t proc, int info_class, void *buf, uint32_t len,
                                  uint32_t *out_len) {
    pid_t pid = handle_to_pid(proc);

    switch (info_class) {
    case JV_PROC_BASIC: {
        struct {
            int32_t exit;
            void *peb;
            uint64_t aff;
            int32_t prio;
            uint64_t pid;
            uint64_t parent;
        } info = {0};
        info.pid = (uint64_t)pid;
        /* windows normal priority class. ignored on linux. */
        info.prio = 8;
        size_t copy = (len < sizeof(info)) ? len : sizeof(info);
        memcpy(buf, &info, copy);
        if (out_len)
            *out_len = (uint32_t)sizeof(info);
        return JV_OK;
    }
    case JV_PROC_DEBUG_PORT: {
        /* windows debug port is a handle. on linux returns 0
         * and the eBPF tracepoint catches ptrace instead. */
        uint32_t port = 0;
        size_t copy = (len < sizeof(port)) ? len : sizeof(port);
        memcpy(buf, &port, copy);
        if (out_len)
            *out_len = (uint32_t)sizeof(port);
        return JV_OK;
    }
    case JV_PROC_IMAGE_NAME: {
        /* readlink /proc/PID/exe. fails for setuid binaries or if
         * the kernel has hidepid=2 mounted. no workaround available. */
        char path[512];
        char link[64];
        snprintf(link, sizeof(link), "/proc/%d/exe", pid);
        ssize_t rc = readlink(link, path, sizeof(path) - 1);
        if (rc < 0)
            return JV_ERR_DENIED;
        path[rc] = '\0';
        size_t copy = (len < (size_t)rc + 1) ? len : (size_t)rc + 1;
        memcpy(buf, path, copy);
        if (out_len)
            *out_len = (uint32_t)(rc + 1);
        return JV_OK;
    }
    default:
        if (buf)
            memset(buf, 0, len);
        if (out_len)
            *out_len = len;
        return JV_OK;
    }
}

/* ==========================================================================
 * NtOpenProcess
 * ========================================================================== */

jv_result_t jv_open_process(jv_handle_t *out, uint32_t access, void *client_id) {
    (void)access;
    if (!out || !client_id)
        return JV_ERR_INVALID;

    pid_t pid = *(pid_t *)client_id;
    if (pid <= 0)
        return JV_ERR_DENIED;

    /* kill(pid, 0) checks if the process exists without sending a signal.
     * EPERM indicates the process exists but cannot be signalled. */
    if (kill(pid, 0) != 0 && errno != EPERM)
        return JV_ERR_DENIED;

    /* yama ptrace_scope check. prevents returning a handle that cannot
     * be used for process_vm_readv. */
    int scope = get_ptrace_scope();
    if (scope == 3)
        return JV_ERR_DENIED;
    if (scope == 2 && !has_cap_sys_ptrace())
        return JV_ERR_DENIED;
    if (scope == 1 && !is_descendant(getpid(), pid))
        return JV_ERR_DENIED;

    jv_handle_t h = alloc_handle(HND_PROCESS);
    if (h == JV_INVALID_HANDLE)
        return JV_ERR_NOMEM;
    struct hnd_entry *e = resolve_handle(h);
    e->u.pid = pid;
    *out = h;
    return JV_OK;
}

jv_result_t jv_close_handle(jv_handle_t h) {
    struct hnd_entry *e = resolve_handle(h);
    if (!e)
        return JV_ERR_INVALID;
    free_handle_entry(e);
    return JV_OK;
}

/* ==========================================================================
 * NtReadVirtualMemory / NtWriteVirtualMemory
 * ========================================================================== */

jv_result_t jv_read_memory(jv_handle_t proc, void *addr, void *buf, uint32_t len,
                           uint32_t *out_len) {
    pid_t pid = handle_to_pid(proc);
    struct iovec local = {.iov_base = buf, .iov_len = len};
    struct iovec remote = {.iov_base = addr, .iov_len = len};
    ssize_t rc = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    if (rc < 0) {
        if (out_len)
            *out_len = 0;
        return JV_ERR_DENIED;
    }
    if (out_len)
        *out_len = (uint32_t)rc;
    return JV_OK;
}

jv_result_t jv_write_memory(jv_handle_t proc, void *addr, const void *buf, uint32_t len,
                            uint32_t *out_len) {
    pid_t pid = handle_to_pid(proc);
    struct iovec local = {.iov_base = (void *)buf, .iov_len = len};
    struct iovec remote = {.iov_base = addr, .iov_len = len};
    ssize_t rc = process_vm_writev(pid, &local, 1, &remote, 1, 0);
    if (rc < 0) {
        if (out_len)
            *out_len = 0;
        return JV_ERR_DENIED;
    }
    if (out_len)
        *out_len = (uint32_t)rc;
    return JV_OK;
}

/* ==========================================================================
 * NtProtectVirtualMemory
 * ========================================================================== */

jv_result_t jv_protect_memory(jv_handle_t proc, void **addr, uint32_t *len, uint32_t prot,
                              uint32_t *old_prot) {
    (void)proc;
    long ps = sysconf(_SC_PAGESIZE);
    void *page = (void *)(((uintptr_t)*addr) & ~(ps - 1));
    size_t plen = *len;
    if (page != *addr)
        plen += (size_t)((uintptr_t)*addr - (uintptr_t)page);

    pid_t pid = handle_to_pid(proc);
    uint32_t prev = 0;
    if (get_page_protection(pid, page, &prev) == 0) {
        if (old_prot)
            *old_prot = prev;
    } else {
        if (old_prot)
            *old_prot = JV_PROT_NONE;
    }

    if (mprotect(page, plen, prot_from_jv(prot)) != 0)
        return JV_ERR_DENIED;

    return JV_OK;
}

/* ==========================================================================
 * NtAllocateVirtualMemory
 * ========================================================================== */

jv_result_t jv_alloc_memory(jv_handle_t proc, void **addr, uint32_t *len, uint32_t flags,
                            uint32_t prot) {
    (void)proc;
    if (!addr || !len)
        return JV_ERR_INVALID;

    void *want = *addr;
    int real_prot = prot_from_jv(prot);

    if ((flags & JV_MEM_RESERVE) && !(flags & JV_MEM_COMMIT)) {
        /* reserve only: no physical backing */
        int mflags = MAP_PRIVATE | MAP_ANONYMOUS;
        if (want != NULL) {
#ifdef MAP_FIXED_NOREPLACE
            mflags |= MAP_FIXED_NOREPLACE;
#else
            mflags |= MAP_FIXED;
#endif
        }
        void *mem = mmap(want, *len, PROT_NONE, mflags, -1, 0);
        if (mem == MAP_FAILED)
            return JV_ERR_DENIED;
        *addr = mem;
        return JV_OK;
    }

    if (!(flags & JV_MEM_RESERVE) && (flags & JV_MEM_COMMIT) && want != NULL) {
        /* commit an existing reservation. mprotect to back with pages. */
        long ps = sysconf(_SC_PAGESIZE);
        void *page = (void *)(((uintptr_t)want) & ~(ps - 1));
        size_t plen = *len;
        if (page != want)
            plen += (size_t)((uintptr_t)want - (uintptr_t)page);
        if (mprotect(page, plen, real_prot) != 0)
            return JV_ERR_DENIED;
        return JV_OK;
    }

    /* reserve and commit, or commit with NULL addr */
    int mflags = MAP_PRIVATE | MAP_ANONYMOUS;
    if (want != NULL && (flags & JV_MEM_TOPDOWN)) {
#ifdef MAP_FIXED_NOREPLACE
        mflags |= MAP_FIXED_NOREPLACE;
#else
        mflags |= MAP_FIXED;
#endif
    }

    void *mem = mmap(want, *len, real_prot, mflags, -1, 0);
    if (mem == MAP_FAILED)
        return JV_ERR_DENIED;

    *addr = mem;
    return JV_OK;
}

/* ==========================================================================
 * NtFreeVirtualMemory
 * ========================================================================== */

#define JV_MEM_DECOMMIT 0x00004000
#define JV_MEM_RELEASE  0x00008000

jv_result_t jv_free_memory(jv_handle_t proc, void **addr, uint32_t *len, uint32_t free_type) {
    (void)proc;
    if (!addr || !len)
        return JV_ERR_INVALID;
    if (*addr == NULL)
        return JV_OK;

    if (free_type == JV_MEM_DECOMMIT) {
        /* decommit: remove physical backing but keep reservation.
         * linux has no exact equivalent. mprotect to PROT_NONE
         * is the closest approximation. */
        long ps = sysconf(_SC_PAGESIZE);
        void *page = (void *)(((uintptr_t)*addr) & ~(ps - 1));
        size_t plen = *len;
        if (page != *addr)
            plen += (size_t)((uintptr_t)*addr - (uintptr_t)page);
        if (mprotect(page, plen, PROT_NONE) != 0)
            return JV_ERR_DENIED;
        return JV_OK;
    }

    /* release (or default) */
    if (munmap(*addr, *len) != 0)
        return JV_ERR_DENIED;
    *addr = NULL;
    *len = 0;
    return JV_OK;
}

/* ==========================================================================
 * NtFlushInstructionCache
 * ========================================================================== */

jv_result_t jv_flush_icache(jv_handle_t proc, void *addr, uint32_t len) {
    (void)proc;
    if (addr && len > 0)
        __builtin___clear_cache((char *)addr, (char *)addr + len);
    return JV_OK;
}

/* ==========================================================================
 * NtCreateThread
 * ========================================================================== */

typedef union {
    void *p;
    void *(*fn)(void *);
} jv_fnptr;

static void *thread_trampoline(void *arg) {
    void **params = arg;
    jv_fnptr u;
    u.p = params[0];
    void *(*fn)(void *) = u.fn;
    void *fn_arg = params[1];
    free(params);
    return fn(fn_arg);
}

jv_result_t jv_create_thread(jv_handle_t *out, void *start, void *arg) {
    if (!out || !start)
        return JV_ERR_INVALID;

    void **params = malloc(sizeof(void *) * 2);
    if (!params)
        return JV_ERR_NOMEM;
    params[0] = start;
    params[1] = arg;

    pthread_t tid;
    int rc = pthread_create(&tid, NULL, thread_trampoline, params);
    if (rc != 0) {
        free(params);
        return JV_ERR_DENIED;
    }

    jv_handle_t h = alloc_handle(HND_THREAD);
    if (h == JV_INVALID_HANDLE) {
        pthread_detach(tid);
        free(params);
        return JV_ERR_NOMEM;
    }
    struct hnd_entry *e = resolve_handle(h);
    e->u.thread = tid;
    *out = h;
    return JV_OK;
}

/* ==========================================================================
 * NtDebugActiveProcess / NtRemoveProcessDebug
 * ========================================================================== */

jv_result_t jv_debug_attach(jv_handle_t proc) {
    pid_t pid = handle_to_pid(proc);
    if (pid <= 0)
        return JV_ERR_INVALID;
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        switch (errno) {
        case EPERM:
            return JV_ERR_DENIED;
        case ESRCH:
            return JV_ERR_DENIED;
        case EBUSY:
            return JV_ERR_DENIED;
        default:
            return JV_ERR_DENIED;
        }
    }
    int status;
    if (waitpid(pid, &status, 0) < 0)
        return JV_ERR_DENIED;
    return JV_OK;
}

jv_result_t jv_debug_detach(jv_handle_t proc) {
    pid_t pid = handle_to_pid(proc);
    /* ignore errors. ESRCH indicates the process has already exited. */
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return JV_OK;
}

/* ==========================================================================
 * NtQueryValueKey
 * ========================================================================== */

jv_result_t jv_query_value(void *key, void *name, uint32_t class, void *buf, uint32_t len,
                           uint32_t *out_len) {
    (void)key;
    (void)name;
    (void)class;
    if (!buf && len != 0)
        return JV_ERR_INVALID;
    if (buf)
        memset(buf, 0, len);
    if (out_len)
        *out_len = 0;
    return JV_OK;
}

/* ==========================================================================
 * NtCreateFile
 * ========================================================================== */

/* windows disposition constants */
#define JV_FILE_CREATE_NEW       1
#define JV_FILE_CREATE_ALWAYS    2
#define JV_FILE_OPEN_EXISTING    3
#define JV_FILE_OPEN_ALWAYS      4
#define JV_FILE_TRUNCATE_EXISTING 5

/* windows access constants */
#define JV_FILE_GENERIC_READ  0x80000000U
#define JV_FILE_GENERIC_WRITE 0x40000000U

jv_result_t jv_create_file(jv_handle_t *out, const char *path, uint32_t access,
                           uint32_t disposition) {
    if (!path || !out)
        return JV_ERR_INVALID;

    int flags = 0;
    if ((access & JV_FILE_GENERIC_READ) && (access & JV_FILE_GENERIC_WRITE))
        flags = O_RDWR;
    else if (access & JV_FILE_GENERIC_WRITE)
        flags = O_WRONLY;
    else
        flags = O_RDONLY;

    switch (disposition) {
    case JV_FILE_CREATE_NEW:
        flags |= O_CREAT | O_EXCL;
        break;
    case JV_FILE_CREATE_ALWAYS:
        flags |= O_CREAT | O_TRUNC;
        break;
    case JV_FILE_OPEN_EXISTING:
        break;
    case JV_FILE_OPEN_ALWAYS:
        flags |= O_CREAT;
        break;
    case JV_FILE_TRUNCATE_EXISTING:
        flags |= O_TRUNC;
        break;
    default:
        flags |= O_CREAT;
        break;
    }

    int fd = open(path, flags, 0644);
    if (fd < 0)
        return JV_ERR_DENIED;

    jv_handle_t h = alloc_handle(HND_FILE);
    if (h == JV_INVALID_HANDLE) {
        close(fd);
        return JV_ERR_NOMEM;
    }
    struct hnd_entry *e = resolve_handle(h);
    e->u.fd = fd;
    *out = h;
    return JV_OK;
}

/* ==========================================================================
 * callback registration
 * ========================================================================== */

jv_result_t jv_register_callbacks(void *reg, void **out) {
    (void)reg;
    if (!out)
        return JV_ERR_INVALID;
    static unsigned int cb_handle = 1;
    *out = (void *)(uintptr_t)cb_handle++;
    return JV_OK;
}

void jv_unregister_callbacks(void *cb) { (void)cb; }

/* ==========================================================================
 * lifecycle
 * ========================================================================== */

static void cleanup_all_handles(void) {
    pthread_mutex_lock(&handle_mutex);
    for (int i = 0; i < MAX_HANDLES; i++) {
        if (handle_table[i].type != HND_NONE)
            free_handle_entry(&handle_table[i]);
    }
    pthread_mutex_unlock(&handle_mutex);
}

int jv_init(void) {
    if (prctl(PR_SET_DUMPABLE, 0) < 0)
        return -1;
    jv_attestation_start();
    return 0;
}

void jv_fini(void) {
    jv_attestation_stop();
    cleanup_all_handles();
}
