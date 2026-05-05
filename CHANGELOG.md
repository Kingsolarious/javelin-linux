# changelog

## unreleased

- eBPF skeleton with ringbuf and PID filter (CO-RE compatible)
- LSM/file_mprotect hook with memory integrity hashing
- ptrace tracepoint for debugger detection
- kernel_read_file hook for module load monitoring
- proper kallsyms detector (character-by-character match in eBPF)
- LSM/bpf hook for foreign eBPF load detection
- clock_gettime tracepoint for timer anomaly detection (speed hack detection)
- libbpf loader with privilege drop
- privilege drop bug fixed (aborts if SUDO_UID missing)
- MAP_FIXED_NOREPLACE instead of MAP_FIXED
- null checks in syscall proxy
- proper thread trampoline avoiding void*-to-function-pointer UB
- memscan benchmark (process_vm_readv throughput >5GB/s)
- seccomp-bpf sandbox
- attestation service with system state checks (ptrace_scope, secure boot)
- systemd service
- protobuf schema for backend attestation
- flatpak manifest
- docs/research-notes.md with real citations
- docs/ea-javelin-error-codes.md collated from public sources
- scripts for syscall tracing and EAC client analysis

## 0.1.0 - 2026-04-29

- initial scaffold
- userland shim
- ebpf lsm agent
- unit tests
- integration tests
