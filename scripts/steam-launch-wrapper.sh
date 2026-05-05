#!/usr/bin/env bash
# steam/proton launch wrapper
# usage: put this in game launch options as:
#   /path/to/steam-launch-wrapper.sh %command%

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

: "${JAVELIN_COMPAT_PREFIX:=/usr/local}"
: "${JAVELIN_EBPF_OBJECT:=${JAVELIN_COMPAT_PREFIX}/lib/javelin/ebpf/javelin_monitor.bpf.o}"
: "${JAVELIN_SHIM_PATH:=${JAVELIN_COMPAT_PREFIX}/lib/javelin/libjavelin_linux.so}"
: "${JAVELIN_LOADER:=${JAVELIN_COMPAT_PREFIX}/bin/javelin-loader}"
: "${JAVELIN_LOG_LEVEL:=warn}"
: "${JAVELIN_SKIP_EBPF:=0}"
: "${JAVELIN_USE_POLKIT:=1}"

LOADER_PID=""
GAME_PID=""

log_info()  { echo "[javelin-launch] INFO: $*" >&2; }
log_warn()  { echo "[javelin-launch] WARN: $*" >&2; }
log_error() { echo "[javelin-launch] ERROR: $*" >&2; }

cleanup() {
    log_info "cleaning up..."

    if [[ -n "$GAME_PID" ]] && kill -0 "$GAME_PID" 2>/dev/null; then
        log_info "waiting for game process $GAME_PID to exit..."
        wait "$GAME_PID" 2>/dev/null || true
    fi

    if [[ -n "$LOADER_PID" ]] && kill -0 "$LOADER_PID" 2>/dev/null; then
        log_info "stopping eBPF loader (pid $LOADER_PID)..."
        kill -TERM "$LOADER_PID" 2>/dev/null || true
        wait "$LOADER_PID" 2>/dev/null || true
    fi

    rm -f /run/javelin/ebpf.sock
    log_info "cleanup complete."
}
trap cleanup EXIT INT TERM

preflight() {
    log_info "javelin linux compatibility launcher"
    log_info "shim: ${JAVELIN_SHIM_PATH}"
    log_info "eBPF: ${JAVELIN_EBPF_OBJECT}"

    if [[ ! -f "$JAVELIN_SHIM_PATH" ]]; then
        log_error "shim library not found at ${JAVELIN_SHIM_PATH}"
        exit 1
    fi

    if [[ "$JAVELIN_SKIP_EBPF" != "1" && ! -f "$JAVELIN_EBPF_OBJECT" ]]; then
        log_warn "eBPF object not found at ${JAVELIN_EBPF_OBJECT}"
        log_warn "eBPF agent will not be loaded (degraded mode)"
        JAVELIN_SKIP_EBPF=1
    fi

    if [[ "$JAVELIN_SKIP_EBPF" != "1" && ! -f /sys/kernel/btf/vmlinux ]]; then
        log_warn "kernel BTF not available. eBPF needs CONFIG_DEBUG_INFO_BTF=y"
        log_warn "falling back to userland-only attestation."
        JAVELIN_SKIP_EBPF=1
    fi
}

launch_ebpf() {
    if [[ "$JAVELIN_SKIP_EBPF" == "1" ]]; then
        log_info "skipping eBPF load (userland-only mode)"
        return 0
    fi

    if [[ ! -x "$JAVELIN_LOADER" ]]; then
        log_warn "loader binary not executable at ${JAVELIN_LOADER}"
        return 1
    fi

    if [[ -f /sys/fs/bpf/javelin/programs/javelin_mprotect_check ]]; then
        log_info "eBPF programs already pinned in kernel"
        return 0
    fi

    log_info "loading eBPF attestation agent..."

    if [[ "$JAVELIN_USE_POLKIT" == "1" ]] && command -v pkexec >/dev/null 2>&1; then
        pkexec "$JAVELIN_LOADER" "$JAVELIN_EBPF_OBJECT" &
        LOADER_PID=$!
    elif [[ "$EUID" -eq 0 ]]; then
        "$JAVELIN_LOADER" "$JAVELIN_EBPF_OBJECT" &
        LOADER_PID=$!
    else
        if command -v sudo >/dev/null 2>&1; then
            sudo -v 2>/dev/null || true
            sudo "$JAVELIN_LOADER" "$JAVELIN_EBPF_OBJECT" &
            LOADER_PID=$!
        else
            log_warn "cannot load eBPF agent: neither pkexec nor sudo available"
            return 1
        fi
    fi

    local waited=0
    while [[ ! -S /run/javelin/ebpf.sock ]] && [[ $waited -lt 50 ]]; do
        sleep 0.1
        waited=$((waited + 1))
    done

    if [[ -S /run/javelin/ebpf.sock ]]; then
        log_info "eBPF agent ready"
    else
        log_warn "eBPF socket did not appear; continuing in degraded mode"
    fi
}

setup_proton() {
    export WINEDLLOVERRIDES="javelin=n,b${WINEDLLOVERRIDES:+;$WINEDLLOVERRIDES}"
    export JAVELIN_COMPAT_PREFIX
    export JAVELIN_EBPF_OBJECT
    export JAVELIN_REGROOT="${JAVELIN_COMPAT_PREFIX}/var/lib/javelin-compat/reg"
    export JAVELIN_LOG_LEVEL
    export JAVELIN_SECCOMP=1

    mkdir -p "$JAVELIN_REGROOT"

    log_info "proton overrides configured: ${WINEDLLOVERRIDES}"
}

main() {
    preflight
    launch_ebpf
    setup_proton

    log_info "launching game..."
    log_info "command: $*"

    "$@" &
    GAME_PID=$!

    log_info "game started (pid $GAME_PID)"

    wait "$GAME_PID"
    local exit_code=$?

    log_info "game exited with code $exit_code"
    return $exit_code
}

main "$@"
