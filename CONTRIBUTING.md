# Contributing

Pull requests welcome. All changes must compile and pass tests.

## Permitted Sources

- Public Microsoft NT API documentation
- Wine source code (LGPL)
- Linux kernel source (GPL-2.0)
- Syscall traces from legally purchased games

## Prohibited Sources

- Leaked proprietary source or internal documentation
- Decompiled binaries
- Cheat forums or bypass tutorials

## Standards

- C11 for shim and eBPF
- eBPF must pass kernel verifier on 5.15+ and 6.x
- All syscalls require unit tests
- No hardcoded secrets
