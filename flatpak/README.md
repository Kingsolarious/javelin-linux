# flatpak packaging

for ROG ally / steam deck.

## build

```bash
cd flatpak
flatpak-builder --user --install --force-clean build-dir com.ea.javelin-compat.yml
```

## usage

add to steam launch options:
```
flatpak run com.ea.javelin-compat %command%
```

## permissions

- `/sys/fs/bpf:rw` — pin eBPF maps and programs
- `/sys/kernel/btf:ro` — read kernel BTF
- `/run/javelin:create` — unix socket for shim->loader
- `device=all` — GPU and TPM
- `talk-name=org.freedesktop.PolicyKit1` — elevate for eBPF loading

## known issues

- eBPF loading inside flatpak needs polkit. prompts for sudo password once per boot.
- kernel lockdown on some steamOS versions blocks custom eBPF loads.
  shim falls back to userland-only mode.
