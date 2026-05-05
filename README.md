# javelin-linux

erick wants to play battlefield on his asus ROG ally. this is our attempt to make
that possible.

## what this is

a linux compatibility layer for EA's javelin anti-cheat. the windows
javelin DLL loads under proton, and this shim translates its NT API
calls to linux equivalents. an eBPF agent provides kernel-level
attestation without loading kernel modules.

**no EA proprietary code is present.** we reverse engineered the
interface from public docs and wine source. production deployment
requires EA's participation (signed certificate, backend whitelist).

## why dump everything now

we have been working on this locally for about two months. kept it
offline while we figured things out. today i decided to just put it
all up at once because i was tired of sitting on it.

i used some AI tools to help organize the upload because my local
files were a mess and ive been juggling too many projects. it probably
fucked some stuff up. if something looks wrong, thats why. the code
itself is real, i just got lazy with the repo organization.

## architecture

```
game (proton) -> javelin.dll -> libjavelin_linux.so -> eBPF LSM hooks
```

- **shim** (`libjavelin_linux.so`): translates windows NT APIs to linux
- **eBPF agent**: monitors memory, ptrace, and module loads via LSM hooks
- **proton integration**: native DLL override, no proton patches needed

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

last verified run on nicks zephyrus G16:
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
