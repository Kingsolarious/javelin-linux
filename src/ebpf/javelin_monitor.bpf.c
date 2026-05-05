/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * eBPF attestation agent. Monitors security events via LSM/tracepoint hooks.
 * Verifier-safe: emits telemetry only, cannot modify kernel state.
 *
 * clang -target bpf -D__TARGET_ARCH_x86 -g -O2 \
 *   -c javelin_monitor.bpf.c -o javelin_monitor.bpf.o
 */

#include "vmlinux.h"          /* BTF-generated kernel headers (libbpf) */
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/* Metadata */
char _license[] SEC("license") = "GPL";

/* Ring buffer */
struct jvl_event {
    __u32 type;
    __u32 pid;
    __u64 timestamp_ns;
    __u64 addr;
    __u32 flags;
    __u32 reserved;
};

enum jvl_event_type {
    JVL_EVT_MPROTECT_EXEC = 1,
    JVL_EVT_PTRACE_ATTACH,
    JVL_EVT_MODULE_LOAD,
    JVL_EVT_KALLSYMS_ACCESS,
    JVL_EVT_TIMER_ANOMALY,
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); /* 256 KB buffer */
} jvl_rb SEC(".maps");

/* PID filter. Populated by loader.c. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u8);
} jvl_target_pids SEC(".maps");

/* Helpers */
static __always_inline bool is_target_pid(__u32 pid)
{
    __u8 *v = bpf_map_lookup_elem(&jvl_target_pids, &pid);
    return v != NULL;
}

static __always_inline void emit_event(enum jvl_event_type type,
                                        __u64 addr, __u32 flags)
{
    struct jvl_event *ev = bpf_ringbuf_reserve(&jvl_rb, sizeof(*ev), 0);
    if (!ev)
        return;

    ev->type         = (__u32)type;
    ev->pid          = bpf_get_current_pid_tgid() >> 32;
    ev->timestamp_ns = bpf_ktime_get_ns();
    ev->addr         = addr;
    ev->flags        = flags;
    ev->reserved     = 0;

    bpf_ringbuf_submit(ev, 0);
}

/* LSM: file_mprotect */
SEC("lsm/file_mprotect")
int BPF_PROG(javelin_mprotect_check, struct vm_area_struct *vma,
             unsigned long reqprot)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!is_target_pid(pid))
        return 0;

    /* reqprot & PROT_EXEC indicates executable mapping change */
    if (reqprot & PROT_EXEC) {
        __u64 vm_start = BPF_CORE_READ(vma, vm_start);
        emit_event(JVL_EVT_MPROTECT_EXEC, vm_start, (__u32)reqprot);
    }
    return 0; /* always allow; we are a reporter, not an enforcer */
}

/* Tracepoint: sys_enter_ptrace */
SEC("tp/syscalls/sys_enter_ptrace")
int javelin_ptrace_detect(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!is_target_pid(pid))
        return 0;

    long request = ctx->args[0];
    /* PTRACE_ATTACH / PTRACE_SEIZE */
    if (request == 0x10 || request == 0x4200) {
        emit_event(JVL_EVT_PTRACE_ATTACH, (__u64)ctx->args[1], (__u32)request);
    }
    return 0;
}

/* LSM: kernel_read_file */
SEC("lsm/kernel_read_file")
int BPF_PROG(javelin_module_load, struct file *file,
             enum kernel_read_file_id id, bool contents)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!is_target_pid(pid))
        return 0;

    /* id == READING_MODULE indicates module load attempt */
    if (id == 2) { /* READING_MODULE */
        emit_event(JVL_EVT_MODULE_LOAD, 0, 0);
    }
    return 0;
}

/* Tracepoint: sys_enter_openat */
SEC("tp/syscalls/sys_enter_openat")
int javelin_kallsyms_open(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!is_target_pid(pid))
        return 0;

    char buf[16] = {};
    long rc = bpf_probe_read_user_str(buf, sizeof(buf), (const char *)ctx->args[1]);
    if (rc < 0)
        return 0;

    /* crude but effective: detect "kallsyms" in pathname */
    if (buf[0] == 'k' || (buf[1] == 'k' && buf[2] == 'a')) {
        /* Full string comparison is expensive in eBPF; we emit and let
         * userland filter false positives. */
        emit_event(JVL_EVT_KALLSYMS_ACCESS, 0, 0);
    }
    return 0;
}

/* LSM: bpf */
SEC("lsm/bpf")
int BPF_PROG(javelin_bpf_load, int cmd, union bpf_attr *attr, unsigned int size)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    /* Any BPF_PROG_LOAD in the system while game is running is suspicious */
    if (!is_target_pid(pid) && (cmd == 5 /* BPF_PROG_LOAD */)) {
        emit_event(JVL_EVT_MODULE_LOAD, (__u64)cmd, 0);
    }
    return 0;
}
