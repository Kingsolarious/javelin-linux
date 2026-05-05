# javelin vs other anti-cheat stuff

## correction

earlier versions said EAC and battleye use kernel modules. they dont.
theyre userspace-based on linux.

we also incorrectly implied that battlefield uses EAC or battleye. it
doesnt. EA uses their own proprietary kernel-level anti-cheat called
**EA Javelin Anticheat** (unrelated to this project). fucked that up.

## what actually blocks battlefield on linux

- **EA Javelin Anticheat**: kernel-mode on windows. proprietary. no linux
  support. used in battlefield 2042, battlefield V, EA FC, and others.
- **EAC linux**: userspace. closed source. some titles have proton support
  enabled (e.g. apex legends), but battlefield is not one of them because
  battlefield doesnt use EAC.
- **battleye linux**: userspace. closed source. some titles work on linux.
  battlefield doesnt use battleye either.

**the actual problem**: battlefield uses EA's own anti-cheat. there is no
linux build of EA Javelin Anticheat and EA has not enabled proton support.
a job posting from march 2026 mentions exploring linux/proton support but
nothing is shipping yet.

## architecture comparison

| | windows | linux |
|---|---|---|
| EA Javelin Anticheat | kernel driver | does not exist |
| EAC | kernel driver | userspace |
| battleye | kernel driver | userspace |
| **javelin (this project)** | n/a | eBPF LSM hooks |

on linux, EAC and battleye run as userspace processes with normal user
privileges. they do not load kernel modules on linux. our project uses
eBPF LSM hooks, which do require elevated privileges to load.

## naming clarification

**this project is not affiliated with EA Javelin Anticheat.** we named it
before we knew EA trademarked the same name. were not trying to replace
EA's windows kernel driver. were just exploring whether an open-source
eBPF telemetry agent could work for linux gamers since EA offers nothing.

## what we actually do differently

EAC, battleye, and EA Javelin are closed-source publisher-controlled
solutions. we are not trying to replace them.

javelin (this project) is an open-source eBPF telemetry agent. it reports
security events. it does not block cheats. a backend decides what to do
with the reports.

whether this is better or worse isnt the point. no publisher uses eBPF
for anti-cheat telemetry and we wanted to see if it could work.

## honest limitations

- no publisher partner
- no backend integration
- no signing infrastructure
- pre-boot compromise detection needs secure boot
- a root-level attacker can unload the ebpf programs
- we are not EA and cannot make battlefield run on linux by ourselves

## bottom line

we built this because erick wants battlefield on his ROG ally. EA doesnt
support linux. were exploring whether eBPF telemetry could fill that gap
but without EA's cooperation no third-party tool can fully solve this.
