# research notes

what we actually know vs what were guessing. keeping this honest so we
dont get fucked again.

---

## what we know for sure

### EA Javelin Anticheat

- **name**: EA Javelin Anticheat (trademarked april 2025, confirmed by
  USPTO filing and EA security blog)
- **type**: kernel-level anti-cheat on windows. runs as a minifilter
  driver (`EAAntiCheat.sys`, altitude 363250 per community research)
- **usage**: battlefield 2042 (season 6+), battlefield V, battlefield 6,
  EA FC 24/25/26, F1 games, madden
- **requirements**: Secure Boot, TPM 2.0 on some titles (confirmed by EA
  support docs and player reports)
- **linux status**: no linux support. no proton compatibility enabled.
- **EA job posting (march 2026)**: EA is hiring a senior engineer to port
  Javelin to ARM64 and "chart a path for Linux and Proton support."
  source: EA careers site, reported by TechPowerUp, ItsFOSS, ResetEra.

### EAC Linux (closest real example)

- EAC ships a native linux userspace client (`libeasyanticheat.so`) for
  proton-enabled games.
- it does NOT run under wine. proton provides a bridge between the
  windows game and the native linux anti-cheat.
- valve added syscall interception patches (kernel 5.11+) to make this
  work.
- developers must opt-in via the EOS developer portal. its not automatic.
- sources: Epic Games blog (sept 2021), The Verge, Proton GitHub issues.

### BattlEye Linux

- similar to EAC: native linux userspace client, proton bridge.
- developers must opt-in.
- source: BattlEye CEO statement to The Verge (sept 2021).

### Windows NT APIs commonly used by anti-cheat

from public microsoft docs and anti-cheat research:

| windows NT API | what anti-cheat uses it for | our linux equivalent |
|---|---|---|
| `NtQuerySystemInformation` | CPU count, page size, memory info | `jv_query_system_info` -> `sysconf()` |
| `NtQueryInformationProcess` | PID, PEB, image name, debug port | `jv_query_process_info` -> `/proc` |
| `NtOpenProcess` | get handle to game process | `jv_open_process` -> `kill(pid, 0)` |
| `NtReadVirtualMemory` | scan game memory for cheats | `jv_read_memory` -> `process_vm_readv()` |
| `NtWriteVirtualMemory` | patch game memory (rare) | `jv_write_memory` -> `process_vm_writev()` |
| `NtProtectVirtualMemory` | detect W->X transitions | `jv_protect_memory` -> `mprotect()` |
| `NtAllocateVirtualMemory` | allocate scan buffers | `jv_alloc_memory` -> `mmap()` |
| `NtFreeVirtualMemory` | free buffers | `jv_free_memory` -> `munmap()` |
| `NtFlushInstructionCache` | after code patches | `jv_flush_icache` -> `__builtin___clear_cache()` |
| `NtCreateThread` | injection detection | `jv_create_thread` -> `pthread_create()` |
| `NtDebugActiveProcess` / `NtRemoveProcessDebug` | detect debuggers | `jv_debug_attach` -> `ptrace(PTRACE_ATTACH)` |

sources:
- Microsoft NT API docs (public)
- s4dbrd.github.io "How Kernel Anti-Cheats Work" (feb 2026)
- VAC module reversal research (unknowncheats, 2025)
- various cheat forum threads documenting anti-cheat behavior

---

## what we dont know

### EA Javelin's actual API

- we have NOT reverse engineered the javelin DLL interface.
- EA has not published any API docs.
- the functions in our shim (`jv_*`) are based on common NT API patterns
  used by anti-cheat systems in general. they MAY map to javelin's
  actual exports, or they may not. we wont know without access to the
  actual DLL.

### EA Javelin's wire protocol

- the protobuf schema in `proto/attestation.proto` is entirely
  speculative. we have no knowledge of EA's backend protocol.
- it is loosely based on common patterns: event batches, hardware
  fingerprints, challenge-response. this is informed guesswork.

### Whether this will ever work

- without EA enabling proton support or publishing a linux client, no
  third-party shim can make battlefield run online.
- offline/single-player might be a different story, but we havent tested
  that.

---

## open questions to investigate

1. can we get a syscall trace of EA Javelin's usermode DLL using a
   legally purchased copy of the game? (not reverse engineering, just
   observing API calls)
2. what does the EAC linux client actually export? can we study it as a
   reference for how to structure a linux anti-cheat shim?
3. has anyone documented the proton bridge mechanism valve uses for EAC?
4. what specific NT APIs does EA Javelin call? community reverse
   engineering might exist.

---

## sources

- EA security blog: "Fighting for Fairness: Anti-Cheat Progress Report"
  (april 2025) — confirms Javelin is kernel-level
- VG247: "Battlefield 6 is the first Battlefield to launch with EA's new
  kernel-level Javelin Anticheat" (aug 2025)
- GamingOnLinux anti-cheat compatibility list — confirms battlefield
  titles use "EA Javelin Anticheat"
- EA job posting (march 2026): "Chart a path for EA Javelin Anticheat to
  support additional OS and hardware in the future, such as Linux and
  Proton"
- Epic Games blog (sept 2021): EAC Linux/Proton support announcement
- The Verge (sept 2021): "EAC has come to Linux and BattlEye is inbound"
- Fedora Discussion forum (aug 2025): "Kernel level anticheat and Linux:
  how it works?" — confirms EAC/BE are userspace-only on linux
- s4dbrd.github.io: "How Kernel Anti-Cheats Work" (feb 2026) —
  architecture deep-dive

### Proton anti-cheat bridge

- valve and epic collaborated in 2021 to make EAC work on linux/proton.
- the solution: proton provides a bridge. the windows game still loads the
  windows EAC DLL, but EAC's linux client (`libeasyanticheat.so`) runs
  natively on linux. proton translates between them.
- valve added syscall interception patches to the linux kernel (5.11+)
  so wine can handle raw syscalls that anti-cheats use.
- developers must opt-in via the EOS developer portal. its not automatic.
- sources: Epic Games blog (sept 2021), The Verge (sept 2021),
  Valve Proton GitHub discussions
