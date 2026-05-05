# changelog

## unreleased

- initial eBPF skeleton with ring buffer and PID filter
- added lsm/file_mprotect hook for W->X transitions
- added ptrace tracepoint
- added kernel_read_file hook for module loads
- added kallsyms access detection (janky partial string match)
- added lsm/bpf hook for foreign eBPF loads
- wrote libbpf loader with privilege drop
- fixed loader privilege drop bug (now aborts if SUDO_UID missing)
- fixed MAP_FIXED to use MAP_FIXED_NOREPLACE
- added NULL checks to syscall proxy
- added memscan benchmark suite
- added seccomp-bpf sandbox
- added systemd service file
- added protobuf attestation schema
- added flatpak manifest for ROG ally / steam deck
- unit tests pass (test_javelin, test_seccomp)
- integration tests pass (library exports, seccomp, unit tests)

## 0.1.0 - 2026-04-29

- initial project scaffold
- userland shim with NT->linux syscall proxy
- eBPF LSM agent for kernel telemetry
- unit tests for syscall proxy and attestation
- integration test suite
