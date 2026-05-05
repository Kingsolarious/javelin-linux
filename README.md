# javelin-linux

erick wants to play battlefield on his asus ROG ally. this is our attempt to make
that possible.

## what this is

an experimental linux telemetry agent for games that use kernel-level
anti-cheat. we built it because EA doesnt support linux for battlefield
and we wanted to see if eBPF could fill the gap.

the userland shim implements common windows NT APIs that anti-cheats use
for process introspection and memory scanning. the eBPF agent monitors
kernel events via LSM hooks — no kernel modules, no rootkit behavior.

**whats actually novel here:**
- eBPF LSM hooks for anti-cheat telemetry (no publisher does this)
- CO-RE compatible eBPF (works across kernel versions without recompilation)
- memory integrity baseline: hashes .text regions on W->X transitions
- timer anomaly detection via `clock_gettime` syscall tracing
- privilege-dropping loader (loads eBPF, then drops to user)

**honest limitations:**
- we dont know EA javelin's actual API (its proprietary and undocumented)
- the shim is based on generic windows NT patterns, not reverse engineering
- no backend exists yet. the protobuf schema is speculative.
- no publisher partner. this is a proof of concept.
- production deployment requires EA's cooperation (signed cert, backend)
- seccomp filter is probably too restrictive for wine/proton. games might crash.
- syscall numbers in seccomp are hardcoded for x86_64. arm64 is broken.

**no EA proprietary code is present.**

## why dump everything now

we have been working on this locally for about two months. kept it
offline while we figured things out. today i decided to just put it
all up at once because i was tired of sitting on it.

my local files were a mess and i got lazy organizing the repo. threw it all up at once. probably fucked some stuff up. code itself is real though.

## architecture

```
game -> libjavelin_linux.so (NT API shim) -> eBPF LSM hooks
                                        -> attestation service
```

- **shim** (`libjavelin.so`): windows NT API implementations for linux.
  maps NtReadVirtualMemory to process_vm_readv, NtProtectVirtualMemory to
  mprotect, etc. see `docs/research-notes.md` for the full mapping.
- **eBPF agent** (`javelin_monitor.bpf.o`): LSM hooks for file_mprotect,
  kernel_read_file, bpf loads, ptrace, openat, and clock_gettime. emits
  events to a ring buffer. does not block — pure telemetry.
- **attestation service**: pulls eBPF events, checks system security state
  (ptrace_scope, secure boot), computes memory integrity hashes on W->X
  transitions, and prints telemetry reports.

## testing

unit tests and a memory scan benchmark are included. they build and pass
on nicks machine.

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
./build/memscan_benchmark
```

the eBPF loader needs `libbpf` installed. without it, the loader binary
wont build but the shim and tests still compile.

last verified run on nicks zephyrus G16 (bazzite 43, kernel 6.17.7):
- `test_javelin`: 7/7 passed
- `test_seccomp`: passed
- `memscan_benchmark`: completed
- integration tests: library exports, seccomp, unit tests passed. eBPF
  syntax check skipped if `vmlinux.h` is not generated.

## project structure

```
src/shim/          # userland compatibility layer
src/ebpf/          # kernel telemetry agent
tests/             # unit, integration, and performance tests
scripts/           # build automation
systemd/           # service unit
flatpak/           # handheld packaging (ROG ally, steam deck)
proto/             # backend attestation wire protocol
```

## requirements

- linux kernel 5.15+ with CONFIG_BPF=y, CONFIG_BPF_LSM=y
- clang 14+, cmake 3.20+
- libbpf 1.0+ (optional; for eBPF loader)
- proton experimental or wine staging 8.0+

**known issues:**
- ubuntu 22.04 ships libbpf 0.5 which is too old. use the ppa or build from source.
- fedora 43 works out of the box. fedora 42 needed a kernel arg for BPF_LSM.
- steamos 3.5 has BTF but bpftool is missing. install it via pacman.
- bazzite 43 works. bazzite 41 needed `rpm-ostree karg` for BPF_LSM.

## building

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

## who we are

nick, erick, dyllan. three friends who met in real life.

nick has a 2024 asus ROG zephyrus G16 GU605MY. he wrote most of the
code and lives in california.

erick has an asus ROG ally and wants to play battlefield. he also
lives in california.

dyllan has a 2026 asus tuf F16 with an RTX 5060. he moved to montana
so we collaborate over discord.

this is a nights-and-weekends project. we have day jobs.

## license

- eBPF: GPL-2.0-or-later
- shim: GPL-3.0-or-later
- docs: CC-BY-SA-4.0

## contact

solarsystemsdsp@protonmail.com

---

*not affiliated with electronic arts. javelin is EA's trademark.*
