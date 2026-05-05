# flatpak packaging for ROG ally / steam deck

## build

```bash
cd flatpak
flatpak-builder --user --install --force-clean build-dir com.ea.javelin-compat.yml
```

## usage

after installation, add this to steam game launch options on your handheld:
```
flatpak run com.ea.javelin-compat %command%
```

## permissions

| permission | purpose |
|------------|---------|
| /sys/fs/bpf:rw | pin eBPF maps and programs |
| /sys/kernel/btf:ro | read kernel BTF for CO-RE |
| /run/javelin:create | UNIX socket for shim->loader |
| device=all | GPU and TPM access |
| talk-name=org.freedesktop.PolicyKit1 | elevate for eBPF loading |

## known issues

- eBPF loading inside flatpak needs polkit. on ROG ally / steam deck this
  prompts for sudo password once per boot.
- kernel lockdown mode on some steamOS versions may block custom eBPF
  loads. shim falls back to userland-only mode.
