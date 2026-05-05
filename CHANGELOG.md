# Changelog

## Unreleased

### Added
- Handle tracking table for thread and file lifecycle management
- `jv_open_process` validates YAMA `ptrace_scope` and `CAP_SYS_PTRACE`
- `jv_protect_memory` reads old protection bits from `/proc/PID/maps`
- `jv_alloc_memory` implements `MEM_RESERVE` vs `MEM_COMMIT` semantics
- `jv_free_memory` supports `MEM_DECOMMIT`
- Architecture detection in CMake (`x86_64`, `aarch64`)
- `src/platform/linux/arch.h` with architecture-specific address space constants
- Cross-process memory read integration test (`test_cross_process`)
- `JV_SYS_PERFORMANCE` info class (uptime, load average, CPU frequency)

### Fixed
- Attestation race condition on uninitialized `pthread_t`
- `jv_create_thread` handle leak on allocation failure
- Clang Debug build failure (missing `<unistd.h>` in tests)
- Unit test unused variable warnings in Release builds

### Changed
- All source code comments standardized to dry technical style
- Documentation rewritten in technical manual style
- CI updated with `libbpf-dev`, `linux-tools-generic`, eBPF compilation step

## 0.1.0 — 2026-04-29

- Initial scaffold
- Userland shim
- eBPF LSM agent
- Unit and integration tests

## 0.1.0 — 2026-04-29

- Initial scaffold
- Userland shim
- eBPF LSM agent
- Unit and integration tests
