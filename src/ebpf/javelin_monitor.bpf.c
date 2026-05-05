/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * eBPF agent. LSM/tracepoint hooks.
 * emits events only. does not block.
 */

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

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
    __uint(max_entries, 256 * 1024);
} jvl_rb SEC(".maps");

/* populated by loader. 16 entries is plenty — we're monitoring
 * one game process, maybe the launcher. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u8);
} jvl_target_pids SEC(".maps");

/* per-pid last timestamp for timer anomaly detection.
 * if we see clock_gettime(CLOCK_MONOTONIC) firing way too fast,
 * somebody is speeding up the game timer. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u64);
} jvl_last_time SEC(".maps");

static __always_inline bool is_target_pid(__u32 pid) {
    __u8 *v = bpf_map_lookup_elem(&jvl_target_pids, &pid);
    return v != NULL;
}

static __always_inline void emit_event(enum jvl_event_type type, __u64 addr, __u32 flags) {
    struct jvl_event *ev = bpf_ringbuf_reserve(&jvl_rb, sizeof(*ev), 0);
    if (!ev)
        return;

    ev->type = (__u32)type;
    ev->pid = bpf_get_current_pid_tgid() >> 32;
    ev->timestamp_ns = bpf_ktime_get_ns();
    ev->addr = addr;
    ev->flags = flags;
    ev->reserved = 0;

    bpf_ringbuf_submit(ev, 0);
}

/* compare user string against "/proc/kallsyms" character by character.
 * eBPF verifier rejects bounded loops on user pointers.
 * memcmp helpers are unavailable in BPF_PROG_TYPE_LSM.
 * unrolled character comparison is the only approach that passes
 * on kernel 5.15+. */
static __always_inline bool is_kallsyms(const char *path) {
    char buf[16];
    long rc = bpf_probe_read_user_str(buf, sizeof(buf), path);
    if (rc < 0)
        return false;

    /* "/proc/kallsyms" = 14 chars + null = 15 */
    if (rc != 15)
        return false;

    return buf[0] == '/' && buf[1] == 'p' && buf[2] == 'r' && buf[3] == 'o' && buf[4] == 'c' &&
           buf[5] == '/' && buf[6] == 'k' && buf[7] == 'a' && buf[8] == 'l' && buf[9] == 'l' &&
           buf[10] == 's' && buf[11] == 'y' && buf[12] == 'm' && buf[13] == 's';
}

SEC("lsm/file_mprotect")
int BPF_PROG(javelin_mprotect_check, struct vm_area_struct *vma, unsigned long reqprot) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!is_target_pid(pid))
        return 0;

    if (reqprot & PROT_EXEC) {
        __u64 vm_start = BPF_CORE_READ(vma, vm_start);
        emit_event(JVL_EVT_MPROTECT_EXEC, vm_start, (__u32)reqprot);
    }
    return 0;
}

SEC("tp/syscalls/sys_enter_ptrace")
int javelin_ptrace_detect(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!is_target_pid(pid))
        return 0;

    long request = ctx->args[0];
    /* PTRACE_ATTACH = 0x10, PTRACE_SEIZE = 0x4200 */
    if (request == 0x10 || request == 0x4200) {
        emit_event(JVL_EVT_PTRACE_ATTACH, (__u64)ctx->args[1], (__u32)request);
    }
    return 0;
}

SEC("lsm/kernel_read_file")
int BPF_PROG(javelin_module_load, struct file *file, enum kernel_read_file_id id, bool contents) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!is_target_pid(pid))
        return 0;

    /* READING_MODULE = 2. kernel_read_file_id enum is stable
     * since 4.19. before that the values were different. */
    if (id == 2) {
        emit_event(JVL_EVT_MODULE_LOAD, 0, 0);
    }
    return 0;
}

SEC("tp/syscalls/sys_enter_openat")
int javelin_kallsyms_open(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!is_target_pid(pid))
        return 0;

    if (is_kallsyms((const char *)ctx->args[1])) {
        emit_event(JVL_EVT_KALLSYMS_ACCESS, 0, 0);
    }
    return 0;
}

/* detect foreign eBPF loads while game is running.
 * this is paranoid — if a cheater loads their own eBPF to
 * patch our hooks, we want to know. */
SEC("lsm/bpf")
int BPF_PROG(javelin_bpf_load, int cmd, union bpf_attr *attr, unsigned int size) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!is_target_pid(pid) && cmd == 5 /* BPF_PROG_LOAD */) {
        emit_event(JVL_EVT_MODULE_LOAD, (__u64)cmd, 0);
    }
    return 0;
}

/* detect timer anomalies (speed hacks).
 * monitors clock_gettime(CLOCK_MONOTONIC). if the interval between
 * calls is impossibly small, the game timer is being manipulated.
 *
 * threshold tuned to avoid false positives on common hardware. */
SEC("tp/syscalls/sys_enter_clock_gettime")
int javelin_timer_check(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!is_target_pid(pid))
        return 0;

    /* only monitor CLOCK_MONOTONIC (1). REALTIME is useless for
     * game timing and wall clock changes are normal. */
    if (ctx->args[0] != 1)
        return 0;

    __u64 now = bpf_ktime_get_ns();
    __u64 *last = bpf_map_lookup_elem(&jvl_last_time, &pid);
    if (last) {
        __u64 delta = now - *last;
        /* threshold: 50ms. most games call clock_gettime at 60-240Hz
         * which is ~4-16ms. 50ms catches egregious speed hacks
         * without false positives on overloaded systems. */
        if (delta > 0 && delta < 50000000ULL) {
            emit_event(JVL_EVT_TIMER_ANOMALY, now - *last, 0);
        }
        *last = now;
    } else {
        bpf_map_update_elem(&jvl_last_time, &pid, &now, BPF_ANY);
    }
    return 0;
}
