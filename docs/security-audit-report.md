# Security Audit Notes

Date: April 2026
Scope: Manual code review of C and eBPF source

## Build Verification

- GCC 15.2.1: Clean build
- Clang 21.1.8: Clean build
- clang-tidy: Static analysis completed

## Issues Fixed

- Loader continued as root if `SUDO_UID` missing. Now aborts.
- `MAP_FIXED` used without `NOREPLACE`. Fixed.
- NULL pointer dereferences in syscall proxy. Added checks.
- `prctl(PR_SET_DUMPABLE, 0)` failure ignored. Now returns error.

## eBPF Verifier Guarantees

- No unbounded loops
- No raw pointer arithmetic
- Cannot modify kernel state
- Reports only via ring buffer

## Limitations

- Pre-boot compromise cannot be detected from inside the kernel
- eBPF subsystem compromise would invalidate hash checks
- Userland shim is open-source and can be modified
- No backend exists to verify reports

## Recommendations

This is a starting point, not a finished product. A professional red team assessment is recommended before production deployment.
