# javelin vs existing linux anti-cheat

## correction

earlier versions said EAC and battleye use kernel modules. they dont.
theyre userspace-based. we fixed this.

## architecture

EAC linux: userspace. closed source.
battleye linux: userspace. closed source.
javelin: eBPF LSM hooks. open source.

all three need elevated privs for kernel-level monitoring.

## what we actually do differently

EAC and battleye are closed-source solutions for whitelisted titles.
we are not trying to replace them.

javelin is an open-source eBPF telemetry agent. it reports security
events. it does not block cheats. a backend decides what to do with
the reports.

whether this is better or worse is not the point. no publisher
currently uses eBPF for anti-cheat telemetry, and we wanted to see if
it could work.

## honest limitations

- no publisher partner
- no backend integration
- no signing infrastructure
- pre-boot compromise detection needs secure boot
- a root-level attacker can unload the ebpf programs

## bottom line

we built this because erick wants battlefield on his ROG ally. EAC and
battleye dont support it. were exploring whether eBPF telemetry could
fill that gap.
