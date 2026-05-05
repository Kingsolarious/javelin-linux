#!/usr/bin/env bash
# analyze EAC linux client exports when an EAC-enabled game is installed
# usage: ./analyze-eac-client.sh <path/to/libeasyanticheat.so>
# or run without args and itll search common steam library paths

set -euo pipefail

EAC_SO="${1:-}"

find_eac() {
    find ~/.local/share/Steam/steamapps/common \
         ~/Games \
         /mnt/*/SteamLibrary/steamapps/common 2>/dev/null \
         -name "libeasyanticheat.so" -o -name "easyanticheat_x64.so" | head -5
}

if [[ -z "$EAC_SO" ]]; then
    echo "searching for EAC linux client..."
    EAC_SO=$(find_eac | head -1)
fi

if [[ -z "$EAC_SO" || ! -f "$EAC_SO" ]]; then
    echo "couldnt find EAC client. install an EAC-enabled linux game"
    echo "(e.g. rocket league, fall guys) or pass the .so path manually."
    exit 1
fi

echo "analyzing: $EAC_SO"
echo ""

echo "=== exports ==="
nm -D "$EAC_SO" | grep " T " | awk '{print $3}' | sort

echo ""
echo "=== strings (filtered) ==="
strings "$EAC_SO" | grep -E "^EAC|^Easy|GetProcAddress|NtQuery|NtRead|NtProtect|NtAllocate|wine|proton" | sort -u | head -50

echo ""
echo "=== dependencies ==="
ldd "$EAC_SO" 2>/dev/null || echo "ldd failed (expected for some .so files)"

echo ""
echo "=== file info ==="
file "$EAC_SO"
