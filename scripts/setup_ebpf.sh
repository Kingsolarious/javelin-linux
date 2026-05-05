#!/usr/bin/env bash
# eBPF dev environment setup
# usage: ./scripts/setup_ebpf.sh [install|check|build]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

check_deps() {
    local missing=()

    command -v clang >/dev/null 2>&1 || missing+=("clang")
    command -v llc >/dev/null 2>&1   || missing+=("llvm")
    command -v bpftool >/dev/null 2>&1 || missing+=("bpftool")
    command -v cmake >/dev/null 2>&1 || missing+=("cmake")

    if [[ -f /boot/config-$(uname -r) ]]; then
        local kconfig="/boot/config-$(uname -r)"
    elif [[ -f /proc/config.gz ]]; then
        local kconfig="/proc/config.gz"
    else
        log_warn "cant find kernel config; assuming features are enabled"
        local kconfig=""
    fi

    if [[ -n "$kconfig" ]]; then
        local check_cmd
        if [[ "$kconfig" == *.gz ]]; then
            check_cmd="zgrep"
        else
            check_cmd="grep"
        fi

        $check_cmd -q "CONFIG_BPF=y" "$kconfig" 2>/dev/null || log_warn "CONFIG_BPF not enabled"
        $check_cmd -q "CONFIG_BPF_SYSCALL=y" "$kconfig" 2>/dev/null || log_warn "CONFIG_BPF_SYSCALL not enabled"
        $check_cmd -q "CONFIG_BPF_LSM=y" "$kconfig" 2>/dev/null || log_warn "CONFIG_BPF_LSM not enabled"
        $check_cmd -q "CONFIG_DEBUG_INFO_BTF=y" "$kconfig" 2>/dev/null || log_warn "CONFIG_DEBUG_INFO_BTF not enabled"
    fi

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "missing dependencies: ${missing[*]}"
        echo ""
        echo "debian/ubuntu:"
        echo "  sudo apt-get install clang llvm libbpf-dev bpftool cmake linux-headers-\$(uname -r)"
        echo ""
        echo "fedora:"
        echo "  sudo dnf install clang llvm libbpf-devel bpftool cmake kernel-headers"
        echo ""
        echo "arch:"
        echo "  sudo pacman -S clang llvm libbpf bpftool cmake linux-headers"
        exit 1
    fi

    log_info "all dependencies satisfied"
}

setup_runtime() {
    log_info "setting up runtime directories..."

    sudo mkdir -p /sys/fs/bpf/javelin/programs
    sudo mkdir -p /sys/fs/bpf/javelin/maps
    sudo mkdir -p /run/javelin
    sudo mkdir -p /var/lib/javelin-compat/reg

    if ! mountpoint -q /sys/fs/bpf; then
        log_info "mounting bpffs..."
        sudo mount -t bpf none /sys/fs/bpf
    fi

    sudo chmod 0755 /run/javelin
    sudo chmod 0755 /var/lib/javelin-compat

    log_info "runtime directories ready"
}

build_ebpf() {
    log_info "building eBPF programs..."

    local src="$PROJECT_ROOT/src/ebpf/javelin_monitor.bpf.c"
    local out="$PROJECT_ROOT/build/javelin_monitor.bpf.o"
    local arch="$(uname -m)"

    local target_arch
    case "$arch" in
        x86_64)  target_arch="x86" ;;
        aarch64) target_arch="arm64" ;;
        *)       log_error "unsupported architecture: $arch"; exit 1 ;;
    esac

    mkdir -p "$PROJECT_ROOT/build"

    clang -target bpf \
        -D__TARGET_ARCH_${target_arch} \
        -I/usr/include/${arch}-linux-gnu \
        -I/usr/include/bpf \
        -g -O2 \
        -c "$src" \
        -o "$out"

    log_info "eBPF object built: $out"
}

build_shim() {
    log_info "building userland shim..."

    mkdir -p "$PROJECT_ROOT/build"
    cd "$PROJECT_ROOT/build"

    cmake .. -DCMAKE_BUILD_TYPE=Release
    cmake --build . --parallel "$(nproc)"

    log_info "userland shim built"
}

CMD="${1:-all}"

case "$CMD" in
    check)
        check_deps
        ;;
    setup)
        check_deps
        setup_runtime
        ;;
    build-ebpf)
        check_deps
        build_ebpf
        ;;
    build-shim)
        check_deps
        build_shim
        ;;
    build)
        check_deps
        build_ebpf
        build_shim
        ;;
    all)
        check_deps
        setup_runtime
        build_ebpf
        build_shim
        log_info "full build complete. artifacts in $PROJECT_ROOT/build/"
        ;;
    *)
        echo "usage: $0 {check|setup|build-ebpf|build-shim|build|all}"
        exit 1
        ;;
esac
