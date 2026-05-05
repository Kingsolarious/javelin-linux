# Flatpak Packaging

## Build

```bash
cd flatpak
flatpak-builder --user --install --force-clean build-dir com.ea.javelin-compat.yml
```

## Usage

Add to Steam launch options:
```
flatpak run com.ea.javelin-compat %command%
```

## Permissions

- `/sys/fs/bpf:rw` — eBPF map pinning
- `/sys/kernel/btf:ro` — BTF reading
- `/run/javelin:create` — UNIX socket
- `device=all` — GPU and TPM access

## Known Issues

- eBPF loading inside Flatpak requires polkit.
- Kernel lockdown on some SteamOS versions blocks custom eBPF loads.
