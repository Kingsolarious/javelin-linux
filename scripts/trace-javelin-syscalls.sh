#!/usr/bin/env bash
# trace windows API calls from a game running under proton/wine
# usage: ./trace-javelin-syscalls.sh <steam_appid>
# requires: strace, steam, the game installed
# 
# this captures what NT APIs the game (and any loaded anti-cheat DLL)
# actually calls. run it, launch the game from steam, then ctrl-c when
# youre done. the output goes to ./traces/

set -euo pipefail

APPID="${1:-}"
if [[ -z "$APPID" ]]; then
    echo "usage: $0 <steam_appid>"
    echo "example: $0 1517290   # battlefield 2042"
    exit 1
fi

TRACE_DIR="$(dirname "$0")/../traces"
mkdir -p "$TRACE_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUT="$TRACE_DIR/${APPID}_${TIMESTAMP}.log"

echo "tracing appid $APPID..."
echo "launch the game from steam now. press ctrl-c when done."
echo "output: $OUT"

# find the game process once it starts. wine/proton launches a chain
# of processes so we trace the whole tree.
sudo dtrace -n 'syscall:::entry /pid == $target/ { @[probefunc] = count(); }' \
    -p "$(pgrep -f "$APPID" | head -1)" 2>/dev/null || true

# fallback: strace the wine-preloader if dtrace is unavailable
# this is noisy but captures the actual syscalls
if command -v strace >/dev/null 2>&1; then
    echo "falling back to strace..."
    # wait for wine to start, then attach
    while ! pgrep -x "wine64-preloader" >/dev/null 2>&1; do
        sleep 1
    done
    sudo strace -f -e trace=all -o "$OUT" -p "$(pgrep -x "wine64-preloader")"
fi

echo "trace saved to $OUT"
echo "grep for NtReadVirtualMemory, NtProtectVirtualMemory, etc."
