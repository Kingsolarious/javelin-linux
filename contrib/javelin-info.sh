#!/usr/bin/env bash
# javelin-info — print system state relevant to anti-cheat
# usage: ./contrib/javelin-info.sh

set -euo pipefail

red='\033[0;31m'
grn='\033[0;32m'
ylw='\033[1;33m'
nc='\033[0m'

read_file() {
    cat "$1" 2>/dev/null || echo "unknown"
}

echo ""
echo "  ╔══════════════════════════════════════╗"
echo "  ║         javelin system info          ║"
echo "  ╚══════════════════════════════════════╝"
echo ""

# kernel
echo "  kernel:     $(uname -r)"
echo "  arch:       $(uname -m)"
echo "  distro:     $(source /etc/os-release 2>/dev/null && echo "$NAME $VERSION_ID" || echo "unknown")"

# BPF support
if [[ -f /sys/kernel/debug/tracing/events/syscalls/sys_enter_ptrace/id ]]; then
    echo -e "  ptrace tp:  ${grn}available${nc}"
else
    echo -e "  ptrace tp:  ${red}missing${nc}"
fi

if [[ -f /proc/sys/kernel/yama/ptrace_scope ]]; then
    scope=$(cat /proc/sys/kernel/yama/ptrace_scope)
    case "$scope" in
        0) echo -e "  yama:       ${grn}disabled${nc} (scope=0)" ;;
        1) echo -e "  yama:       ${ylw}restricted${nc} (scope=1, needs CAP_SYS_PTRACE)" ;;
        2) echo -e "  yama:       ${red}admin-only${nc} (scope=2)" ;;
        3) echo -e "  yama:       ${red}noattach${nc} (scope=3)" ;;
    esac
else
    echo -e "  yama:       ${ylw}not installed${nc}"
fi

# secure boot
if [[ -f /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c ]]; then
    sb=$(od -An -tx1 -j4 -N1 /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c 2>/dev/null | tr -d ' ')
    if [[ "$sb" == "01" ]]; then
        echo -e "  secureboot: ${grn}enabled${nc}"
    else
        echo -e "  secureboot: ${red}disabled${nc}"
    fi
else
    echo -e "  secureboot: ${ylw}not available${nc} (legacy boot or no EFI)"
fi

# BTF
if [[ -f /sys/kernel/btf/vmlinux ]]; then
    echo -e "  BTF:        ${grn}available${nc}"
else
    echo -e "  BTF:        ${red}missing${nc} (need CONFIG_DEBUG_INFO_BTF=y)"
fi

# BPF LSM
if grep -q "bpf" /sys/kernel/security/lsm 2>/dev/null; then
    echo -e "  BPF LSM:    ${grn}enabled${nc}"
else
    echo -e "  BPF LSM:    ${red}disabled${nc} (need CONFIG_BPF_LSM=y)"
fi

# javelin runtime
if [[ -S /run/javelin/ebpf.sock ]]; then
    echo -e "  loader:     ${grn}running${nc}"
else
    echo -e "  loader:     ${red}not running${nc}"
fi

if lsmod 2>/dev/null | grep -q javelin; then
    echo -e "  shim:       ${grn}loaded${nc}"
else
    echo -e "  shim:       ${ylw}not loaded${nc}"
fi

echo ""
