# javelin-linux

Experimental Linux compatibility layer for Windows anti-cheat systems.

## Overview

This project provides:
- A userland shim (`libjavelin.so`) implementing Windows NT APIs using Linux syscalls
- An eBPF LSM agent for kernel telemetry (memory protection, ptrace, module loading)
- An attestation service for system security state reporting

The eBPF agent emits events only. It does not block or modify kernel state.

## Architecture

```
Game Process -> libjavelin.so (NT API shim) -> eBPF LSM hooks
                                          -> Attestation Service
```

### Components

**libjavelin.so** — Userland compatibility layer. Maps Windows NT APIs to Linux equivalents:
- `NtReadVirtualMemory` -> `process_vm_readv`
- `NtWriteVirtualMemory` -> `process_vm_writev`
- `NtProtectVirtualMemory` -> `mprotect` (old prot bits read from `/proc/PID/maps`)
- `NtAllocateVirtualMemory` -> `mmap` with `MEM_RESERVE`/`MEM_COMMIT` semantics
- `NtCreateThread` -> `pthread_create` with tracked handle lifecycle
- `NtDebugActiveProcess` -> `ptrace`
- `NtOpenProcess` -> validates YAMA `ptrace_scope` and `CAP_SYS_PTRACE`

**eBPF Agent** (`javelin_monitor.bpf.o`) — LSM and tracepoint hooks:
- `lsm/file_mprotect` — W->X transition detection
- `tp/syscalls/sys_enter_ptrace` — Debugger attachment detection
- `lsm/kernel_read_file` — Kernel module load detection
- `tp/syscalls/sys_enter_openat` — `/proc/kallsyms` access detection
- `lsm/bpf` — Foreign eBPF load detection
- `tp/syscalls/sys_enter_clock_gettime` — Timer anomaly detection

**Attestation Service** — Background thread polling eBPF events, checking system state (ptrace_scope, Secure Boot), and computing memory integrity hashes.

## Building

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

### Requirements

- Linux kernel 5.15+
- `CONFIG_BPF=y`, `CONFIG_BPF_LSM=y`, `CONFIG_DEBUG_INFO_BTF=y`
- Clang 14+, CMake 3.20+
- libbpf 1.0+ (optional, for eBPF loader)

### Architecture Support

- x86_64 (primary)
- aarch64 (constants defined, seccomp filter pending)

### Known Issues

See [GitHub Issues](https://github.com/Kingsolarious/javelin-linux/issues) for tracked bugs. Current limitations:
- The seccomp-bpf filter whitelist may be too restrictive for Wine/Proton.
- Syscall numbers in the seccomp filter are hardcoded for x86_64.
- No backend attestation server exists. Reports are emitted to stderr only.

## Project Structure

```
src/javelin/          # Userland shim
src/ebpf/             # eBPF agent and loader
src/platform/linux/   # Platform-specific code (attestation, seccomp)
tests/unit/           # Unit tests
tests/perf/           # Performance benchmarks
tests/integration/    # Integration tests
scripts/              # Build and trace utilities
contrib/              # Community contributions
proto/                # Attestation wire protocol (speculative)
flatpak/              # Flatpak packaging manifest
systemd/              # systemd service unit
```

## License

- eBPF code: GPL-2.0-or-later
- Shim code: GPL-3.0-or-later
- Documentation: CC-BY-SA-4.0
