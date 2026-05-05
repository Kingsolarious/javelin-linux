# security notes

april 2026. we reviewed our own code. no money for a paid audit.

## what we checked

- manual code review of all C and eBPF
- GCC 15.2.1 and clang 21.1.8 builds
- clang-tidy static analysis
- runtime testing

## issues fixed

- loader continued as root if SUDO_UID missing -> now aborts
- MAP_FIXED without NOREPLACE -> fixed
- NULL dereferences -> added checks
- prctl failure ignored -> now returns error

## what the verifier guarantees

- no unbounded loops
- no raw pointer arithmetic
- cannot modify kernel state
- reports only via ring buffer

## what we CANNOT guarantee

pre-boot compromise: if a rootkit loads before our agent, we cant
detect it from inside the kernel. we check /proc/modules and secure
boot status, but a determined attacker can hide their module.

ebpf subsystem compromise: if the verifier or bpf() syscall is patched
before our agent loads, our hash checks are meaningless.

shim tampering: the userland shim is open-source. an attacker can
modify and recompile it. we dont have signing infrastructure yet.

no backend: there is no game backend to verify reports. we built the
client agent. backend integration is a separate problem.

## what this protects against

- casual cheaters unloading a kernel module
- off-the-shelf cheat tools that use ptrace
- self-modifying code (W->X transitions)

## what this does NOT protect against

- determined attackers with root who patch the kernel first
- nation-state level adversaries
- hardware-level attacks

## if youre EA

hire a real red team. dont trust our self-review. this is a starting
point, not a finished product.
