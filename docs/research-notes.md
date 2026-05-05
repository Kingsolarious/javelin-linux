# Research Notes

## Confirmed Facts About EA Javelin Anticheat

- Driver file: `EAAntiCheat.sys` (minifilter altitude 363250)
- Trademark filed: April 2025
- Requires: Secure Boot, TPM 2.0
- Installation path: `C:\Program Files\EA\AC\`

## EAC Linux Bridge (Valve/Epic, 2021)

The closest existing example of anti-cheat Linux support. Architecture:
- Windows game loads `easyanticheat.dll`
- Linux Proton runtime loads `libeasyanticheat.so` (native Linux binary)
- The Linux client communicates with the same EAC backend as Windows
- No kernel module on Linux; userspace-only

Sources:
- Valve Proton source code (BSD-3-Clause)
- Epic Games EAC Linux documentation

## Windows NT API Mapping

| javelin-linux function      | Windows NT API               | Linux implementation |
|-----------------------------|------------------------------|----------------------|
| `jv_read_memory`            | `NtReadVirtualMemory`        | `process_vm_readv`   |
| `jv_write_memory`           | `NtWriteVirtualMemory`       | `process_vm_writev`  |
| `jv_protect_memory`         | `NtProtectVirtualMemory`     | `mprotect`           |
| `jv_alloc_memory`           | `NtAllocateVirtualMemory`    | `mmap`               |
| `jv_free_memory`            | `NtFreeVirtualMemory`        | `munmap`             |
| `jv_flush_icache`           | `NtFlushInstructionCache`    | `__builtin___clear_cache` |
| `jv_create_thread`          | `NtCreateThread`             | `pthread_create`     |
| `jv_debug_attach`           | `NtDebugActiveProcess`       | `ptrace(PTRACE_ATTACH)` |
| `jv_query_system_info`      | `NtQuerySystemInformation`   | `sysinfo`, `sysconf` |
| `jv_query_process_info`     | `NtQueryInformationProcess`  | `/proc/PID/exe`, `getpid` |
| `jv_open_process`           | `NtOpenProcess`              | `kill(pid, 0)`       |

## Unknowns

- Actual Javelin DLL exports and calling convention
- Wire protocol between client and EA backend
- Exact syscall sequence under Proton
