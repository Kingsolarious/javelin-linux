#!/usr/bin/env bash
# Generate vmlinux.h from the running kernel's BTF information.
# This header is required to compile the eBPF programs.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
OUTPUT="${PROJECT_ROOT}/src/ebpf/vmlinux.h"

if ! command -v bpftool >/dev/null 2>&1; then
    echo "Error: bpftool is required. Install it via the distribution package manager."
    exit 1
fi

if [[ ! -f /sys/kernel/btf/vmlinux ]]; then
    echo "Error: Kernel BTF not available at /sys/kernel/btf/vmlinux"
    echo "       Ensure the kernel was built with CONFIG_DEBUG_INFO_BTF=y"
    exit 1
fi

echo "Generating vmlinux.h from kernel BTF..."
bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$OUTPUT"
echo "Written: $OUTPUT"
echo "You can now build the eBPF object with:"
echo "  clang -target bpf -c src/ebpf/javelin_monitor.bpf.c -o javelin_monitor.bpf.o"
