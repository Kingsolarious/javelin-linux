/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * seccomp-bpf filter.
 * locks down the shim after init.
 *
 * WARNING: this whitelist may be too restrictive for Wine/Proton.
 * Wine requires additional syscalls (openat, fstat, etc.).
 * wine-specific allowlist not yet implemented.
 */

#include <linux/errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

/* these numbers are x86_64 only. on arm64 theyre different.
 * arm64 uses different values.
 * use SYS_process_vm_readv from <sys/syscall.h> instead
 * but glibc headers are inconsistent across distros. */
#ifndef __NR_process_vm_readv
#define __NR_process_vm_readv 310
#endif
#ifndef __NR_process_vm_writev
#define __NR_process_vm_writev 311
#endif

int jv_seccomp_install(void) {
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, nr)),

        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_read, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),

        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_write, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),

        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_close, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),

        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_mmap, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),

        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_mprotect, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),

        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_process_vm_readv, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),

        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_process_vm_writev, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),

        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_exit_group, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),

        /* block everything else with ENOSYS. this breaks getpid() which
         * wine uses internally. see TODO.md. */
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | (ENOSYS & SECCOMP_RET_DATA)),
    };

    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
        return -1;
    return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
}
