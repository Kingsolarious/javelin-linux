# todo

- [ ] get a real game to test with (dont have bf6 dev build)
- [ ] actually test the proton wrapper on ericks ROG ally
- [ ] figure out if the attestation socket reconnects properly when loader restarts
- [ ] add arm64 support (ROG ally is x86_64 but future proofing)
- [ ] write better integration tests that dont need root
- [ ] fix the flatpak manifest - not sure if the paths are right

# random notes

- the seccomp filter blocks getpid which breaks some wine internals.
  need to add an exception or wine games will crash.
- ebpf verifier on steamos 3.5 is stricter than on bazzite. had to
  simplify the kallsyms detector.
- proton experimental changed something in dll override behavior and
  now javelin.dll doesnt always load first. need to investigate.
