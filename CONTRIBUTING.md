# contributing

if you want to contribute, open a PR. make sure it compiles and passes
tests. thats it.

## what you can use

- public microsoft NT API docs
- wine source code (LGPL)
- linux kernel source (GPL-2.0)
- your own syscall traces from legally purchased games

## what you cant use

- leaked javelin source or internal EA docs
- decompiled javelin binaries
- cheat forums or bypass tutorials

## code standards

- C11 for shim and eBPF
- eBPF must pass kernel verifier on 5.15+ and 6.x
- all syscalls need unit tests
- no hardcoded secrets

## commit messages

just write what you did. no special format required.

## maintainers

- erick
- nick
- dyllan
