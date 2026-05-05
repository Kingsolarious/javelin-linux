# todo

- [ ] get a real game to test with (dont have bf6 dev build)
- [ ] actually test the proton wrapper on ericks ROG ally
- [ ] fix attestation socket reconnect when loader restarts
- [ ] add arm64 support (ROG ally is x86_64 but steam deck might go arm)
- [ ] write integration tests that dont need root
- [ ] fix the flatpak manifest - not sure if the paths are right
- [ ] add wine/proton syscall exceptions to seccomp filter
- [ ] replace hardcoded x86_64 syscall numbers in seccomp with SYS_*
- [ ] figure out why process_vm_readv fails on yama ptrace_scope=2

# random notes

- the seccomp filter blocks getpid which breaks some wine internals.
  need to add an exception or wine games will crash.
- ebpf verifier on steamos 3.5 is stricter than on bazzite. had to
  simplify the kallsyms detector. same code, different verifier moods.
- need to research proton DLL override behavior once we have a real game to test
- libbpf 1.0+ required. ubuntu 22.04 ships 0.5. debian 12 ships 0.8.
  both are too old. need to document this better.
